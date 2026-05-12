# 📖 KubeGuard Incident Runbook

This document outlines the standard operating procedures for when KubeGuard detects and responds to a runtime security incident.

## 🚨 Alert Received: Pod Isolated

When the **KubeGuard Controller** receives a HIGH/CRITICAL alert from Falco, it automatically:
1.  Labels the pod: `security.kubeguard/status=quarantined`.
2.  Triggers a Slack notification.
3.  Activates the `kubeguard-quarantine-policy` (NetworkPolicy).

### Step 1: Investigation
Check the controller audit logs to see exactly what triggered the event:
```bash
# View the last 50 audit entries in the controller
kubectl exec -it <controller-pod-name> -n kubeguard -- tail -f /tmp/kubeguard_audit.log
```

### Step 2: Verify Isolation
Confirm that the pod is indeed labeled and blocked.
```bash
# Check labels
kubectl get pods -A -l security.kubeguard/status=quarantined

# Verify NetworkPolicy matches
kubectl describe netpol kubeguard-quarantine-policy -n default
```

### Step 3: Forensics
Before deleting the pod, describe it to see images, environment variables, and events.
```bash
kubectl describe pod <quarantined-pod-name>
kubectl logs <quarantined-pod-name>
```

### Step 4: Resolution
If the alert was a **False Positive**:
1. Update the custom Falco rules in `infra/custom-falco-rules.yaml`.
2. Remove the quarantine label:
   ```bash
   kubectl label pod <pod-name> security.kubeguard/status-
   ```

If the alert was **Malicious**:
1. Terminate the pod: `kubectl delete pod <pod-name>`.
2. Update the deployment to fix the vulnerability (e.g., upgrade base image).
3. Re-run the Phase 1 scans locally.

## 🛠️ Maintenance: Adding New Rules
To add a new detection (e.g., detecting `nsenter` execution):
1. Add the rule to `infra/custom-falco-rules.yaml`.
2. Apply changes: `kubectl apply -f infra/custom-falco-rules.yaml`.
3. Restart Falco pods to load the new configuration.
