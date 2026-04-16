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
use semver::{Version, VersionReq};
use std::sync::Arc;
use tokio::sync::Mutex;

const UPSTREAM_REGISTRY: &str = "https://registry.npmjs.org";
const OLD_AUDIT_PATH: &str = "/-/npm/v1/security/audits";
const BULK_ADVISORY_PATH: &str = "/-/npm/v1/security/advisories/bulk";

#[derive(Debug, Clone)]
struct FindingInfo {
    pub version: String,
    pub paths: Vec<String>,
    pub dev: bool,
    pub optional: bool,
    pub bundled: bool,
}

#[derive(Debug)]
struct ParsedAudit {
    /// Packages formatted for the bulk API request.
    /// Example: `{"express": ["1.0.0", "2.0.0"]}`
    pub packages: HashMap<String, Vec<String>>,
    /// Pre-computed paths mapped by `pkg_name -> version -> FindingInfo`
    pub pkg_findings: HashMap<String, HashMap<String, FindingInfo>>,
    /// Minimum depth found for each package name
    pub pkg_min_depth: HashMap<String, usize>,
    /// Total count of dependencies in the tree.
    pub total_deps: u64,
}

/// Parses the audit request by building a flat index of all available package nodes
/// and then traversing the logical tree starting from the root's requires.
fn parse_audit_request(body: &Value) -> ParsedAudit {
    let mut packages: HashMap<String, Vec<String>> = HashMap::new();
    let mut pkg_findings: HashMap<String, HashMap<String, FindingInfo>> = HashMap::new();
    let mut pkg_min_depth: HashMap<String, usize> = HashMap::new();
    let mut total_deps = 0;

    // Pass 1: Collect ALL package nodes from the physical tree (dependencies) into a flat map
    // pkg_name -> version -> node_info
    let mut node_index: HashMap<String, HashMap<String, Value>> = HashMap::new();

    fn collect_nodes(node: &Value, node_index: &mut HashMap<String, HashMap<String, Value>>, total_deps: &mut u64) {
        if let Some(deps_obj) = node.get("dependencies").and_then(|v| v.as_object()) {
            for (pkg_name, pkg_info) in deps_obj {
                *total_deps += 1;
                if let Some(version) = pkg_info.get("version").and_then(|v| v.as_str()) {
                    node_index.entry(pkg_name.clone()).or_default().insert(version.to_string(), pkg_info.clone());
                }
                collect_nodes(pkg_info, node_index, total_deps);
            }
        }
    }
    collect_nodes(body, &mut node_index, &mut total_deps);

    // Pass 2: Trace logical paths starting from root's requires
    // We walk logically: if A requires B, the path is A>B, even if B is a sibling or higher in node_modules
    fn walk_logical(
        node: &Value,
        current_path: &str,
        depth: usize,
        node_index: &HashMap<String, HashMap<String, Value>>,
        packages: &mut HashMap<String, Vec<String>>,
        pkg_findings: &mut HashMap<String, HashMap<String, FindingInfo>>,
        pkg_min_depth: &mut HashMap<String, usize>,
        visited: &mut Vec<String>,
    ) {
        if let Some(requires_obj) = node.get("requires").and_then(|v| v.as_object()) {
            for (pkg_name, range_val) in requires_obj {
                if let Some(range_str) = range_val.as_str() {
                    // Try to find the node that satisfies this requirement
                    // In simple npm audit requests, there's usually just one version of each package or explicit nested ones.
                    // We'll look for any version that fits, or just the one in the index.
                    if let Some(versions) = node_index.get(pkg_name) {
                        for (version_str, pkg_info) in versions {
                            // Basic heuristic: if it's in the index, it's what's installed
                            // (In a real resolver we'd check semver, but here we match what's in node_modules)
                            
                            let path = if current_path.is_empty() {
                                pkg_name.clone()
                            } else {
                                format!("{}>{}", current_path, pkg_name)
                            };

                            // Add to bulk API packages
                            let versions_list = packages.entry(pkg_name.clone()).or_default();
                            if !versions_list.contains(version_str) {
                                versions_list.push(version_str.clone());
                            }

                            // Track min depth
                            let min_depth = pkg_min_depth.entry(pkg_name.clone()).or_insert(depth + 1);
                            if depth + 1 < *min_depth {
                                *min_depth = depth + 1;
                            }

                            // Add finding info
                            let findings = pkg_findings.entry(pkg_name.clone()).or_default();
                            let info = findings.entry(version_str.clone()).or_insert_with(|| FindingInfo {
                                version: version_str.clone(),
                                paths: Vec::new(),
                                dev: pkg_info.get("dev").and_then(|v| v.as_bool()).unwrap_or(false),
                                optional: pkg_info.get("optional").and_then(|v| v.as_bool()).unwrap_or(false),
                                bundled: pkg_info.get("bundled").and_then(|v| v.as_bool()).unwrap_or(false),
                            });
                            if !info.paths.contains(&path) {
                                info.paths.push(path.clone());
                            }

                            // Prevent infinite recursion in cycles
                            if !visited.contains(&path) {
                                visited.push(path.clone());
                                walk_logical(pkg_info, &path, depth + 1, node_index, packages, pkg_findings, pkg_min_depth, visited);
                                visited.pop();
                            }
                        }
                    } else {
                        // Package not found in dependencies, but still add to bulk API if it has a range
                        let versions_list = packages.entry(pkg_name.clone()).or_default();
                        if !versions_list.contains(&range_str.to_string()) {
                            versions_list.push(range_str.to_string());
                        }
                    }
                }
            }
        }
    }

    let mut visited = Vec::new();
    walk_logical(body, "", 0, &node_index, &mut packages, &mut pkg_findings, &mut pkg_min_depth, &mut visited);

    ParsedAudit {
        packages,
        pkg_findings,
        pkg_min_depth,
        total_deps,
    }
}

#[derive(Debug, serde::Deserialize)]
struct PackageMetadata {
    pub versions: HashMap<String, Value>,
}

async fn fetch_package_metadata(client: &Client, pkg_name: &str) -> Option<PackageMetadata> {
    let url = format!("{}/{}", UPSTREAM_REGISTRY, pkg_name);
    let resp = client.get(&url).send().await.ok()?;
    if resp.status().is_success() {
        resp.json().await.ok()
    } else {
        None
    }
}

/// Build the old audit response format from the bulk advisory response using the pre-computed index.
async fn build_old_response(
    client: &Client,
    bulk_response: &Value,
    parsed_audit: &ParsedAudit,
) -> Value {
    let mut advisories: HashMap<String, Value> = HashMap::new();
    let mut actions: Vec<Value> = Vec::new();
    let mut vuln_counts = HashMap::from([
        ("info", 0u64),
        ("low", 0u64),
        ("moderate", 0u64),
        ("high", 0u64),
        ("critical", 0u64),
    ]);

    // Cache for package metadata to avoid redundant fetches
    let mut metadata_cache: HashMap<String, PackageMetadata> = HashMap::new();

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

                    // Retrieve findings from the pre-computed findings map
                    let findings_map = parsed_audit.pkg_findings.get(pkg_name);
                    let findings: Vec<Value> = if let Some(pkg_versions) = findings_map {
                        pkg_versions
                            .iter()
                            .map(|(version, info)| {
                                serde_json::json!({
                                    "version": version,
                                    "paths": info.paths,
                                })
                            })
                            .collect()
                    } else {
                        Vec::new()
                    };

                    // Extract GHSA ID and CVEs from URL or other fields
                    let url_str = advisory.get("url").and_then(|v| v.as_str()).unwrap_or("");
                    let github_advisory_id = if url_str.contains("/GHSA-") {
                        url_str.split('/').last().unwrap_or("").to_string()
                    } else {
                        "".to_string()
                    };

                    let vulnerable_versions = advisory
                        .get("vulnerable_versions")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");

                    // Fetch package metadata to find the best patched version
                    if !metadata_cache.contains_key(pkg_name) {
                        if let Some(md) = fetch_package_metadata(client, pkg_name).await {
                            metadata_cache.insert(pkg_name.clone(), md);
                        }
                    }

                    let mut patched_versions = String::new();
                    let mut target_version = String::new();

                    if let (Some(md), Ok(vuln_req)) = (metadata_cache.get(pkg_name), VersionReq::parse(vulnerable_versions)) {
                        let mut versions: Vec<Version> = md.versions.keys()
                            .filter_map(|v| Version::parse(v).ok())
                            .collect();
                        versions.sort();

                        // Find the first version that DOES NOT satisfy the vulnerable requirement
                        if let Some(first_patched) = versions.iter().find(|v| !vuln_req.matches(v)) {
                            patched_versions = format!(">={}", first_patched);
                            target_version = first_patched.to_string();
                        }
                    }

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
                        "cves": advisory.get("cves").unwrap_or(&serde_json::json!([])),
                        "access": "public",
                        "severity": severity,
                        "module_name": pkg_name,
                        "vulnerable_versions": vulnerable_versions,
                        "github_advisory_id": github_advisory_id,
                        "recommendation": if !target_version.is_empty() {
                            format!("Upgrade {} to version {} or later", pkg_name, target_version)
                        } else {
                            format!("Upgrade {} to a patched version", pkg_name)
                        },
                        "patched_versions": if !patched_versions.is_empty() {
                            patched_versions
                        } else {
                            advisory.get("patched_versions").and_then(|v| v.as_str()).unwrap_or("").to_string()
                        },
                        "updated": "",
                        "cvss": advisory.get("cvss").unwrap_or(&Value::Null),
                        "cwe": advisory.get("cwe").unwrap_or(&Value::Null),
                        "url": url_str,
                    });

                    advisories.insert(id_str, full_advisory);

                    // Build actions for this advisory
                    let depth = parsed_audit.pkg_min_depth.get(pkg_name).cloned().unwrap_or(1);
                    
                    let resolves: Vec<Value> = if let Some(pkg_versions) = findings_map {
                         pkg_versions
                            .iter()
                            .flat_map(|(_, info)| {
                                info.paths.iter().map(|path| {
                                    serde_json::json!({
                                        "id": id,
                                        "path": path,
                                        "dev": info.dev,
                                        "optional": info.optional,
                                        "bundled": info.bundled,
                                    })
                                })
                            })
                            .collect()
                    } else {
                        Vec::new()
                    };

                    if !resolves.is_empty() {
                        actions.push(serde_json::json!({
                            "action": "update",
                            "resolves": resolves,
                            "module": pkg_name,
                            "target": target_version,
                            "depth": depth,
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
            let old_response = build_old_response(client, &bulk_response, &parsed_audit).await;
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
