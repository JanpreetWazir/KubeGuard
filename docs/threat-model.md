# 🛡️ KubeGuard STRIDE Threat Model

This document identifies potential threats to the KubeGuard system and outlines the security controls implemented to mitigate them.

## Threat Analysis Table

| Threat Category | Component | Severity | Mitigation Strategy | Implementation Status |
| :--- | :--- | :--- | :--- | :--- |
| **Spoofing** | Webhook Endpoint | **High** | HMAC-SHA256 signature verification on all incoming Falco alerts. | ✅ Implemented |
| **Tampering** | Alert Data | **Medium** | Payload validation using Pydantic models to ensure data integrity. | ✅ Implemented |
| **Repudiation** | Decision Logic | **Low** | Structured JSON audit logging of all isolation actions (Stored in Volume). | ✅ Implemented |
| **Information Disclosure** | K8s API | **Medium** | Narrow RBAC scoping; limited to `patch` permissions on pods in specific namespaces. | ✅ Implemented |
| **Denial of Service** | Controller API | **High** | Redis-backed alert deduplication to prevent "Alert Storm" resource exhaustion. | ✅ Implemented |
| **Elevation of Priv.** | Controller Pod | **High** | OPA Gatekeeper policy enforcing Read-Only Root FS and No-Privilege mode. | ✅ Implemented |

## Detailed Mitigations

### 1. Webhook Authentication (HMAC)
To prevent unauthorized parties from triggering pod isolation, the controller requires an `X-Falco-Signature` header. This signature is verified against a shared secret using the HMAC-SHA256 algorithm.

### 2. Least-Privilege RBAC
The `kubeguard-sa` ServiceAccount is restricted via a `ClusterRole` to only have the permissions necessary to label pods. It cannot delete resources or view secrets.

### 3. Attack Surface Reduction
The controller binary is built using a `slim` Python base image, reducing the number of installed utilities that could be leveraged by an attacker.

