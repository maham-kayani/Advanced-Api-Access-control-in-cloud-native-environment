"""
CONTROLLED ENVIRONMENT - server-side application (FastAPI)

Runs as the `server-side` pod in the `controlled` namespace.
There is NO security code here on purpose: access is enforced by the
platform, outside the application:
  - Kubernetes NetworkPolicy : only client-side pods, only TCP port 80
  - Istio AuthorizationPolicy: "/" and "/dataset1" allowed, "/dataset2" denied
"""
from fastapi import FastAPI

app = FastAPI(title="server-side")


@app.get("/")
async def public():
    return {"message": "Public endpoint of server-side"}


@app.get("/dataset1")
async def dataset1():
    return {"dataset": "dataset1", "data": [1, 2, 3]}


@app.get("/dataset2")
async def dataset2():
    # Istio denies this path for client-side-sa -> client receives 403 (RBAC: access denied)
    return {"dataset": "dataset2", "data": [4, 5, 6]}
