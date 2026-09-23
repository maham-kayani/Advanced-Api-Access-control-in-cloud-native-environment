"""
UNCONTROLLED ENVIRONMENT - 2) AUTHORIZATION, DEFAULT FLOW  (report section 5.2.2)

Flow for EVERY request (no caching):
  1. Client credentials -> access token (PAT)
  2. Fetch Keycloak public keys and verify the access token
  3. Request an RPT from Keycloak (UMA grant) for "resource#scope"
     -> Keycloak evaluates its policies/permissions
  4. Introspect the RPT at Keycloak's introspection endpoint
  5. Grant access only if the RPT is active and holds the required permission

Report result: ~133.75 ms, 12 exchanges.

Run:  uvicorn authorization:app --port 8000
Test: curl http://localhost:8000/read
"""
import time

import httpx
import jwt
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from loguru import logger

import config

app = FastAPI(title="Uncontrolled - Authorization (default)")


def rtt(label: str, start: float) -> None:
    logger.info(f"{label} RTT: {(time.perf_counter() - start) * 1000:.2f} ms")


async def get_access_token(client: httpx.AsyncClient) -> str:
    start = time.perf_counter()
    r = await client.post(config.TOKEN_URL, data={
        "grant_type": "client_credentials",
        "client_id": config.CLIENT_ID,
        "client_secret": config.CLIENT_SECRET,
    })
    r.raise_for_status()
    rtt("Access token", start)
    return r.json()["access_token"]


async def verify_token(client: httpx.AsyncClient, token: str) -> dict:
    start = time.perf_counter()
    r = await client.get(config.CERTS_URL)          # fetched EVERY time (not cached)
    r.raise_for_status()
    rtt("Public key", start)
    kid = jwt.get_unverified_header(token)["kid"]
    jwk = next((k for k in r.json()["keys"] if k["kid"] == kid), None)
    if jwk is None:
        raise HTTPException(401, "Signing key not found")
    try:
        return jwt.decode(token, jwt.PyJWK(jwk).key, algorithms=["RS256"],
                          issuer=f"{config.KEYCLOAK_URL}/realms/{config.REALM}",
                          options={"verify_aud": False})
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "Token has expired")
    except jwt.InvalidTokenError as e:
        raise HTTPException(401, f"Invalid token: {e}")


async def get_rpt(client: httpx.AsyncClient, access_token: str) -> str:
    start = time.perf_counter()
    r = await client.post(
        config.TOKEN_URL,
        headers={"Authorization": f"Bearer {access_token}"},
        data={
            "grant_type": "urn:ietf:params:oauth:grant-type:uma-ticket",
            "audience": config.RESOURCE_SERVER_CLIENT_ID,
            "permission": config.PERMISSION,
        },
    )
    if r.status_code == 403:
        raise HTTPException(403, "Keycloak policy denied the permission")
    r.raise_for_status()
    rtt("RPT", start)
    return r.json()["access_token"]


async def introspect_rpt(client: httpx.AsyncClient, rpt: str) -> dict:
    start = time.perf_counter()
    r = await client.post(
        config.INTROSPECT_URL,
        auth=(config.RESOURCE_SERVER_CLIENT_ID, config.CLIENT_SECRET),
        data={"token": rpt, "token_type_hint": "requesting_party_token"},
    )
    r.raise_for_status()
    rtt("RPT introspection", start)
    return r.json()


def has_permission(permissions: list, required: str) -> bool:
    resource, _, scope = required.partition("#")
    return any(
        p.get("rsname") == resource and (not scope or scope in p.get("scopes", []))
        for p in permissions
    )


@app.middleware("http")
async def authorize(request: Request, call_next):
    if request.url.path == "/":
        return await call_next(request)
    start = time.perf_counter()
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            access_token = await get_access_token(client)
            await verify_token(client, access_token)
            rpt = await get_rpt(client, access_token)
            info = await introspect_rpt(client, rpt)
        if not info.get("active") or not has_permission(info.get("permissions", []), config.PERMISSION):
            raise HTTPException(403, "RPT does not grant the required permission")
        request.state.rpt = rpt
        response = await call_next(request)
        rtt("TOTAL authorization", start)
        return response
    except httpx.HTTPStatusError as e:
        return JSONResponse({"detail": f"Keycloak error: {e.response.text}"}, e.response.status_code)
    except HTTPException as e:
        return JSONResponse({"detail": e.detail}, e.status_code)


@app.get("/")
async def public_endpoint():
    return {"message": "This is a public endpoint"}


@app.get("/read")
async def protected_endpoint(request: Request):
    return {"message": "Confidential data accessed with a valid RPT"}
