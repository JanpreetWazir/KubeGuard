from prometheus_client import start_http_server, Counter
from fastapi import FastAPI, Request
import uvicorn
from kubernetes import client, config
from pydantic import BaseModel
from typing import Dict, Any , Optional
import redis
import hmac
import hashlib
import os
import requests

import json
import logging
from pythonjsonlogger import jsonlogger

EXCLUDED_NAMESPACES = ["kube-system", "gatekeeper-system", "kubeguard", "kube-public", "kube-node-lease"]


class FalcoAlert(BaseModel):
    hostname: str
    output: str
    priority: str
    rule: str
    source: str
    tags: Optional[list[str]] = []
    output_fields: Dict[str, Any]
SHARED_SECRET = os.getenv("FALCO_SECRET", "default-secret-key")

def verify_signature(payload: bytes, signature: str):
    # Calculate HMAC SHA256
    expected_signature = hmac.new(
        SHARED_SECRET.encode(),
        payload,
        hashlib.sha256
    ).hexdigest()
    
    return hmac.compare_digest(expected_signature, signature)


# Create an Audit Logger
audit_logger = logging.getLogger("audit")
logHandler = logging.FileHandler("/tmp/kubeguard_audit.log") # In prod, this would be a persistent volume
formatter = jsonlogger.JsonFormatter('%(asctime)s %(levelname)s %(message)s')
logHandler.setFormatter(formatter)
audit_logger.addHandler(logHandler)
audit_logger.setLevel(logging.INFO)


# Connect to local Redis (if running controller locally, use localhost)
r = redis.Redis(host=os.getenv("REDIS_HOST", "redis"), port=6379, db=0)

SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")

def send_slack_alert(message):
    if not SLACK_WEBHOOK_URL:
        print("DEBUG: Slack Webhook URL not set. Skipping notification.")
        return
    
    payload = {"text": f"🚨 *KubeGuard Alert* 🚨\n{message}"}
    try:
        response = requests.post(SLACK_WEBHOOK_URL, json=payload)
        if response.status_code != 200:
            print(f"Failed to send Slack alert: {response.text}")
    except Exception as e:
        print(f"Error sending Slack alert: {e}")


app = FastAPI()

ALERTS_RECEIVED = Counter('kubeguard_alerts_total', 'Total Falco alerts received by the controller')
PODS_ISOLATED = Counter('kubeguard_isolations_total', 'Total pods quarantined by the controller')

# Load K8s config (In-cluster if running in K8s, otherwise local kubeconfig)

try:
    config.load_incluster_config()
except config.ConfigException:
    config.load_kube_config()

v1 = client.CoreV1Api()


@app.post("/webhook")
async def receive_alert(request: Request):
    # 1. HMAC check (Keep this first!)
    body = await request.body()
    signature = request.headers.get("X-Falco-Signature")
    if not signature or not verify_signature(body, signature):
        return {"status": "unauthorized"}

    # 2. Parse the alert
    alert_data = json.loads(body)
    alert = FalcoAlert(**alert_data)
    
    # 3. NOW get the namespace and check it
    fields = alert.output_fields
    namespace = fields.get("k8s.ns.name")
    pod_name = fields.get("k8s.pod.name")

    if namespace in EXCLUDED_NAMESPACES:
        print(f"DEBUG: Skipping isolation for system namespace: {namespace}")
        return {"status": "skipped", "reason": "system_namespace"}

    # 4. Continue with metrics and isolation...
    ALERTS_RECEIVED.inc()


    # FalcoAlert is a Pydantic model — use attribute access, not .get()
    fields = alert.output_fields
    pod_name = fields.get("k8s.pod.name")
    namespace = fields.get("k8s.ns.name")
    priority = alert.priority

    print(f"DEBUG: Rule={alert.rule} Pod={pod_name} Priority={priority}")
    
    # Create a unique key for this pod + rule
    dedup_key = f"alert:{alert.rule}:{pod_name}"

    # Try to set the key in Redis with a 60-second expiration (TTL)
    # If the key already exists, 'set' will return None
    is_new_alert = r.set(dedup_key, "active", ex=60, nx=True)

    if not is_new_alert:
        print(f"DEBUG: Dropping duplicate alert for {pod_name}")
        return {"status": "dropped", "reason": "duplicate"}

    # 3. Action Logic: Isolate pod on high-severity alerts
    if priority in ["Critical", "Alert", "Emergency"] and pod_name:
        msg = f"Rule: {alert.rule}\nPod: {pod_name}\nNamespace: {namespace}\nAction: Pod Isolated ✅"
        send_slack_alert(msg)
        isolate_pod(pod_name, namespace)


    return {"status": "ok"}


def isolate_pod(pod_name, namespace):
    print(f"ACTION: Isolating Pod {pod_name} in namespace {namespace}...")

    body = {
        "metadata": {
            "labels": {
                "security.kubeguard/status": "quarantined"
            }
        }
    }

    try:
        v1.patch_namespaced_pod(
            name=pod_name,
            namespace=namespace,
            body=body
        )
        # Log the successful isolation for audit purposes
        audit_logger.info("Pod Isolated", extra={
            "action": "isolate",
            "pod_name": pod_name,
            "namespace": namespace,
            "status": "success",
            "reason": "Security Alert Received"
})

        PODS_ISOLATED.inc()
        print(f"Pod {pod_name} isolated successfully")

    except Exception as e:
        print(f"Failed to isolate pod {pod_name}: {e}")
        # Log the failed isolation for audit purposes
        audit_logger.error("Pod Isolation Failed", extra={
            "action": "isolate",
            "pod_name": pod_name,
            "namespace": namespace,
            "status": "failed",
            "error": str(e)

            
        })


if __name__ == "__main__":
    # Start Prometheus metrics server on port 9000
    start_http_server(9000)
    uvicorn.run(app, host="0.0.0.0", port=8000)