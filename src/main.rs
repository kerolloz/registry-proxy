use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{body::Incoming, Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use reqwest::Client;
use serde_json::Value;
use std::collections::HashMap;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tracing::{error, info, warn};

const UPSTREAM_REGISTRY: &str = "https://registry.npmjs.org";
const OLD_AUDIT_PATH: &str = "/-/npm/v1/security/audits";
const BULK_ADVISORY_PATH: &str = "/-/npm/v1/security/advisories/bulk";

#[derive(Debug)]
struct ParsedAudit {
    /// Packages formatted for the bulk API request.
    /// Example: `{"express": ["1.0.0", "2.0.0"]}`
    pub packages: HashMap<String, Vec<String>>,
    /// Pre-computed paths mapped by `pkg_name -> version -> paths`
    /// This drastically speeds up finding construction later.
    pub pkg_paths: HashMap<String, HashMap<String, Vec<String>>>,
    /// Total count of dependencies in the tree.
    pub total_deps: u64,
}

/// A blazing fast single-pass parser that traverses the dependency tree exactly once.
/// It simultaneously builds the bulk request payload, the paths index, and counts total deps.
fn parse_audit_request(body: &Value) -> ParsedAudit {
    let mut packages: HashMap<String, Vec<String>> = HashMap::new();
    let mut pkg_paths: HashMap<String, HashMap<String, Vec<String>>> = HashMap::new();
    let mut total_deps = 0;

    fn walk(
        deps: &Value,
        current_path: &str,
        packages: &mut HashMap<String, Vec<String>>,
        pkg_paths: &mut HashMap<String, HashMap<String, Vec<String>>>,
        total_deps: &mut u64,
    ) {
        if let Some(deps_obj) = deps.as_object() {
            for (pkg_name, pkg_info) in deps_obj {
                *total_deps += 1;

                let path = if current_path.is_empty() {
                    pkg_name.clone()
                } else {
                    format!("{}>{}", current_path, pkg_name)
                };

                if let Some(version) = pkg_info.get("version").and_then(|v| v.as_str()) {
                    let version_str = version.to_string();

                    // 1. Add to top-level packages array
                    let versions = packages.entry(pkg_name.clone()).or_default();
                    if !versions.contains(&version_str) {
                        versions.push(version_str.clone());
                    }

                    // 2. Add to pre-computed paths index
                    pkg_paths
                        .entry(pkg_name.clone())
                        .or_default()
                        .entry(version_str)
                        .or_default()
                        .push(path.clone());
                }

                // Recurse into nested dependencies
                if let Some(nested_deps) = pkg_info.get("dependencies") {
                    walk(nested_deps, &path, packages, pkg_paths, total_deps);
                }
            }
        }
    }

    if let Some(deps) = body.get("dependencies") {
        walk(deps, "", &mut packages, &mut pkg_paths, &mut total_deps);
    }

    // Also include top-level `requires` packages — use the semver range as-is
    if let Some(requires) = body.get("requires").and_then(|r| r.as_object()) {
        for (pkg_name, version_range) in requires {
            if let Some(range_str) = version_range.as_str() {
                let range = range_str.to_string();
                let versions = packages.entry(pkg_name.clone()).or_default();
                if !versions.contains(&range) {
                    versions.push(range);
                }
            }
        }
    }

    ParsedAudit {
        packages,
        pkg_paths,
        total_deps,
    }
}

/// Build the old audit response format from the bulk advisory response using the pre-computed index.
fn build_old_response(bulk_response: &Value, parsed_audit: &ParsedAudit) -> Value {
    let mut advisories: HashMap<String, Value> = HashMap::new();
    let mut actions: Vec<Value> = Vec::new();
    let mut vuln_counts = HashMap::from([
        ("info", 0u64),
        ("low", 0u64),
        ("moderate", 0u64),
        ("high", 0u64),
        ("critical", 0u64),
    ]);

    if let Some(bulk_obj) = bulk_response.as_object() {
        for (pkg_name, advisories_arr) in bulk_obj {
            if let Some(arr) = advisories_arr.as_array() {
                for advisory in arr {
                    let id = advisory.get("id").and_then(|v| v.as_u64()).unwrap_or(0);
                    let id_str = id.to_string();

                    let severity = advisory
                        .get("severity")
                        .and_then(|v| v.as_str())
                        .unwrap_or("info");

                    // Count vulnerabilities by severity map
                    if let Some(count) = vuln_counts.get_mut(severity) {
                        *count += 1;
                    }

                    // Retrieve findings instantaneously from the pre-computed paths map
                    let findings: Vec<Value> =
                        if let Some(pkg_versions) = parsed_audit.pkg_paths.get(pkg_name) {
                            pkg_versions
                                .iter()
                                .map(|(version, paths)| {
                                    serde_json::json!({
                                        "version": version,
                                        "paths": paths,
                                    })
                                })
                                .collect()
                        } else {
                            Vec::new()
                        };

                    // Build the full advisory object (old format)
                    let full_advisory = serde_json::json!({
                        "findings": findings,
                        "found_by": null,
                        "deleted": null,
                        "references": "",
                        "created": "",
                        "id": id,
                        "npm_advisory_id": null,
                        "overview": "",
                        "reported_by": null,
                        "title": advisory.get("title").unwrap_or(&Value::Null),
                        "metadata": null,
                        "cves": [],
                        "access": "public",
                        "severity": severity,
                        "module_name": pkg_name,
                        "vulnerable_versions": advisory.get("vulnerable_versions").unwrap_or(&Value::Null),
                        "github_advisory_id": "",
                        "recommendation": format!("Upgrade {} to a patched version", pkg_name),
                        "patched_versions": "",
                        "updated": "",
                        "cvss": advisory.get("cvss").unwrap_or(&Value::Null),
                        "cwe": advisory.get("cwe").unwrap_or(&Value::Null),
                        "url": advisory.get("url").unwrap_or(&Value::Null),
                    });

                    advisories.insert(id_str, full_advisory);

                    // Build a basic action for this advisory mapping each path
                    let resolves: Vec<Value> = findings
                        .iter()
                        .flat_map(|f| {
                            f.get("paths")
                                .and_then(|p| p.as_array())
                                .map(|paths| {
                                    paths
                                        .iter()
                                        .map(|path| {
                                            serde_json::json!({
                                                "id": id,
                                                "path": path,
                                                "dev": false,
                                                "optional": false,
                                                "bundled": false,
                                            })
                                        })
                                        .collect::<Vec<_>>()
                                })
                                .unwrap_or_default()
                        })
                        .collect();

                    if !resolves.is_empty() {
                        actions.push(serde_json::json!({
                            "action": "update",
                            "resolves": resolves,
                            "module": pkg_name,
                            "depth": 1,
                        }));
                    }
                }
            }
        }
    }

    serde_json::json!({
        "actions": actions,
        "advisories": advisories,
        "muted": [],
        "metadata": {
            "vulnerabilities": {
                "info": vuln_counts["info"],
                "low": vuln_counts["low"],
                "moderate": vuln_counts["moderate"],
                "high": vuln_counts["high"],
                "critical": vuln_counts["critical"],
            },
            "dependencies": parsed_audit.total_deps,
            "devDependencies": 0,
            "optionalDependencies": 0,
            "totalDependencies": parsed_audit.total_deps,
        }
    })
}

/// Handle the audit endpoint: parse request → bulk API → transform response
async fn handle_audit(
    client: &Client,
    body_bytes: Bytes,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let original_request: Value = match serde_json::from_slice(&body_bytes) {
        Ok(v) => v,
        Err(e) => {
            error!("Failed to parse audit request body: {}", e);
            let resp = Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Full::new(Bytes::from(format!(
                    "{{\"error\": \"Invalid JSON: {}\"}}",
                    e
                ))))
                .unwrap();
            return Ok(resp);
        }
    };

    let parsed_audit = parse_audit_request(&original_request);
    let bulk_request_body = serde_json::to_value(&parsed_audit.packages).unwrap();

    info!(
        "Audit intercepted: transforming {} packages → bulk API",
        parsed_audit.packages.len()
    );

    let bulk_url = format!("{}{}", UPSTREAM_REGISTRY, BULK_ADVISORY_PATH);
    let upstream_resp = client
        .post(&bulk_url)
        .header("Content-Type", "application/json")
        .json(&bulk_request_body)
        .send()
        .await;

    match upstream_resp {
        Ok(resp) => {
            let status = resp.status();
            let resp_bytes = resp.bytes().await.unwrap_or_default();

            if !status.is_success() {
                warn!(
                    "Bulk advisory API returned {}: {}",
                    status,
                    String::from_utf8_lossy(&resp_bytes)
                );
                let response = Response::builder()
                    .status(
                        StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY),
                    )
                    .header("Content-Type", "application/json")
                    .body(Full::new(resp_bytes))
                    .unwrap();
                return Ok(response);
            }

            let bulk_response: Value = serde_json::from_slice(&resp_bytes).unwrap_or(Value::Null);
            let old_response = build_old_response(&bulk_response, &parsed_audit);
            let old_response_bytes = serde_json::to_vec(&old_response).unwrap();

            info!(
                "Audit response transformed successfully ({} deps optimized)",
                parsed_audit.total_deps
            );

            let response = Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "application/json")
                .body(Full::new(Bytes::from(old_response_bytes)))
                .unwrap();
            Ok(response)
        }
        Err(e) => {
            error!("Failed to reach bulk advisory API: {}", e);
            let response = Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .header("Content-Type", "application/json")
                .body(Full::new(Bytes::from(format!(
                    "{{\"error\": \"Upstream error: {}\"}}",
                    e
                ))))
                .unwrap();
            Ok(response)
        }
    }
}

/// Proxy all other requests to the upstream registry seamlessly
async fn proxy_passthrough(
    client: &Client,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let (parts, incoming_body) = req.into_parts();
    let method = parts.method.clone();
    let uri = parts.uri.clone();
    let path_and_query = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");

    let upstream_url = format!("{}{}", UPSTREAM_REGISTRY, path_and_query);

    let mut upstream_req = client.request(method.clone(), &upstream_url);

    for (name, value) in parts.headers.iter() {
        if name != hyper::header::HOST {
            upstream_req = upstream_req.header(name, value);
        }
    }

    let body_bytes = incoming_body.collect().await.unwrap().to_bytes();
    if !body_bytes.is_empty() {
        upstream_req = upstream_req.body(body_bytes.to_vec());
    }

    match upstream_req.send().await {
        Ok(resp) => {
            let status = resp.status();
            let headers = resp.headers().clone();
            let resp_bytes = resp.bytes().await.unwrap_or_default();

            let mut response_builder = Response::builder()
                .status(StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY));

            if let Some(ct) = headers.get("content-type") {
                response_builder = response_builder.header("Content-Type", ct);
            }

            let response = response_builder.body(Full::new(resp_bytes)).unwrap();
            Ok(response)
        }
        Err(e) => {
            error!("Proxy passthrough failed for {}: {}", upstream_url, e);
            let response = Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Full::new(Bytes::from(format!(
                    "{{\"error\": \"Upstream error: {}\"}}",
                    e
                ))))
                .unwrap();
            Ok(response)
        }
    }
}

/// Main request handler — Routes `/audits` vs passthroughs
async fn handle_request(
    client: Client,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let start_time = std::time::Instant::now();

    let res = if method == Method::POST
        && (path == OLD_AUDIT_PATH || path == format!("{}/quick", OLD_AUDIT_PATH))
    {
        let (parts, incoming_body) = req.into_parts();
        let body_bytes = incoming_body.collect().await.unwrap().to_bytes();

        let mut uncompressed_bytes = body_bytes.to_vec();

        if let Some(encoding) = parts.headers.get("content-encoding") {
            if encoding == "gzip" {
                use std::io::Read;
                let mut gz = flate2::read::GzDecoder::new(&body_bytes[..]);
                let mut s = Vec::new();
                if let Ok(_) = gz.read_to_end(&mut s) {
                    uncompressed_bytes = s;
                } else {
                    error!("Failed to decompress gzip body");
                }
            }
        }

        handle_audit(&client, Bytes::from(uncompressed_bytes)).await
    } else {
        proxy_passthrough(&client, req).await
    };

    match &res {
        Ok(response) => {
            info!(
                "{} {} - {} ({:?})",
                method,
                path,
                response.status(),
                start_time.elapsed()
            );
        }
        Err(e) => {
            error!(
                "{} {} - ERROR: {} ({:?})",
                method,
                path,
                e,
                start_time.elapsed()
            );
        }
    }

    res
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(4873);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = TcpListener::bind(addr).await?;

    info!("🚀 Registry Audit Proxy listening on http://{}", addr);
    info!("   Upstream: {}", UPSTREAM_REGISTRY);
    info!("   Intercepts: POST {}", OLD_AUDIT_PATH);
    info!("");
    info!(
        "   Configure npm:  npm set registry http://localhost:{}",
        port
    );
    info!(
        "   Configure yarn: yarn config set registry http://localhost:{}",
        port
    );
    info!("");

    let client = Client::builder().pool_max_idle_per_host(20).build()?;

    loop {
        let (stream, remote_addr) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let client = client.clone();

        tokio::task::spawn(async move {
            let service = service_fn(move |req| {
                let client = client.clone();
                handle_request(client, req)
            });

            if let Err(err) = http1::Builder::new().serve_connection(io, service).await {
                if !err.to_string().contains("connection closed") {
                    error!("Connection error from {}: {}", remote_addr, err);
                }
            }
        });
    }
}
