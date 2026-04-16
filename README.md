# 🚀 Registry Audit Proxy

A blazingly fast, memory-safe Rust proxy that fixes broken `yarn audit` and `pnpm audit` commands by bridging legacy audit requests to the modern npm bulk advisory API.

## ⚠️ The Problem

The npm registry **permanently retired** its legacy security audit endpoints in 2025, returning `HTTP 410 Gone`. This broke security auditing for millions of projects using:

- **Yarn Classic (v1.x)** — Hardcoded to retired endpoints.
- **pnpm v10.x and below** — Uses the same legacy API.

## 💡 The Solution

This proxy acts as a transparent bridge:
1. **Intercepts** legacy `POST /audits` requests.
2. **Transforms** them into modern `bulk advisory` calls.
3. **Reconstructs** the exact legacy JSON response your tools expect.
4. **Proxies** all other registry traffic (installs, metadata) untouched.

---

## ⚡ Quick Start (Docker)

The fastest way to get started is using our pre-built, ultra-slim Distroless image. It’s based on `glibc` for maximum stability and is only ~30MB.

```bash
docker run -p 4873:4873 ghcr.io/kerolloz/registry-proxy:latest
```

---

## 🛠️ Installation Alternatives

### Option 1: Download Pre-built Binary
Download the latest binary for your platform (macOS, Linux, Windows) from the [**Releases**](https://github.com/kerolloz/registry-proxy/releases/latest) page.

### Option 2: Run from Source
Requires the [Rust toolchain](https://rustup.rs/).
```bash
git clone https://github.com/kerolloz/registry-proxy.git
cd registry-proxy
cargo run --release
```

---

## ⚙️ Configuring Your Client

Point your package manager at the proxy instead of the official registry:

```bash
# For yarn
yarn config set registry http://localhost:4873

# For pnpm
pnpm config set registry http://localhost:4873
```

Now run your audits as usual—they will just work again:
```bash
yarn audit
# OR
pnpm audit
```

---

## 🤝 Contributing

Contributions are welcome! Feel free to open an issue or a PR if you have ideas for caching, performance improvements, or better compatibility.

---

## 📄 License

MIT
