from fastapi import FastAPI, Request
import uvicorn
from kubernetes import client, config

app = FastAPI()

# Load K8s config (In-cluster if running in K8s, otherwise local kubeconfig)

try:
    config.load_incluster_config()
except:
    config.load_kube_config()

v1 = client.CoreV1Api()


@app.post("/webhook")
async def receive_alert(request: Request):
    alert = await request.json()

    fields = alert.get("output_fields", {})
    pod_name = fields.get("k8s.pod.name")
    namespace = fields.get("k8s.ns.name")
    priority = alert.get("priority")

    print(f"DEBUG: Rule={alert.get('rule')} Pod={pod_name} Priority={priority}")
    
    # 3. Action Logic: If priority is CRITICAL or Alert contains KubeGuard
    
        # Update this line:
    if priority in ["Notice", "Critical", "Alert", "Emergency"] and pod_name:
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
        print(f"Pod {pod_name} isolated successfully")

    except Exception as e:
        print(f"Failed to isolate pod {pod_name}: {e}")


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)