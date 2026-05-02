# 🛡️ KubeGuard: Phase 1 - Shift-Left Pipeline

KubeGuard is a production-grade DevSecOps project. Phase 1 implements a comprehensive **Shift-Left Security Pipeline** using GitHub Actions.

## 🏗️ Security Architecture

| Security Layer | Tool | Purpose |
| :--- | :--- | :--- |
| **Secrets** | Gitleaks | Blocks AWS keys & K8s tokens (Local Hook + CI) |
| **SAST** | Semgrep & Bandit | Static analysis for Python security vulnerabilities |
| **SCA** | pip-audit & Trivy | Audits dependencies for known CVEs |
| **Container** | Trivy | Scans Docker images; fails build on CRITICAL flaws |
| **IaC** | Checkov | Scans K8s YAML & Helm charts; uploads SARIF reports |
| **SBOM** | Syft | Generates CycloneDX SBOMs on every release tag |

## 🚀 How it Works
1. **Local Barrier**: Pre-commit hooks stop secrets before they leave the developer's laptop.
2. **CI Barrier**: Every PR triggers the `devsecops.yml` suite.
3. **Visibility**: Security results are integrated into the GitHub **Security Tab** via SARIF.
