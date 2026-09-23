"""
UNCONTROLLED ENVIRONMENT - 1) AUTHENTICATION  (report section 5.2.1)

Flow (Client Credentials grant):
  1. Client sends client_id + client_secret to Keycloak token endpoint (POST)
  2. Keycloak returns an access token (JWT)
  3. Resource server verifies the token with Keycloak's public key
     (signature, expiry, issuer)
  4. Valid -> access granted, invalid -> 401

Run:  uvicorn authentication:app --port 8000
Test: curl http://localhost:8000/read
"""
import time

import httpx
import jwt
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from loguru import logger

import config

app = FastAPI(title="Uncontrolled - Authentication")


async def get_access_token(client: httpx.AsyncClient) -> str:
    start = time.perf_counter()
    r = await client.post(config.TOKEN_URL, data={
        "grant_type": "client_credentials",
        "client_id": config.CLIENT_ID,
        "client_secret": config.CLIENT_SECRET,
    })
    r.raise_for_status()
    logger.info(f"Access token RTT: {(time.perf_counter() - start) * 1000:.2f} ms")
    return r.json()["access_token"]


async def verify_token(client: httpx.AsyncClient, token: str) -> dict:
    """Verify signature, expiry and issuer using Keycloak's public key (JWKS)."""
    r = await client.get(config.CERTS_URL)
    r.raise_for_status()
    kid = jwt.get_unverified_header(token)["kid"]
    jwk = next((k for k in r.json()["keys"] if k["kid"] == kid), None)
    if jwk is None:
        raise HTTPException(401, "Signing key not found")
    try:
        return jwt.decode(
            token,
            jwt.PyJWK(jwk).key,
            algorithms=["RS256"],
            issuer=f"{config.KEYCLOAK_URL}/realms/{config.REALM}",
            options={"verify_aud": False},  # client-credentials tokens use aud="account" by default
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "Token has expired")
    except jwt.InvalidTokenError as e:
        raise HTTPException(401, f"Invalid token: {e}")


@app.middleware("http")
async def authenticate(request: Request, call_next):
    if request.url.path == "/":
        return await call_next(request)
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            token = await get_access_token(client)
            claims = await verify_token(client, token)
        request.state.client = claims.get("azp")
        return await call_next(request)
    except httpx.HTTPStatusError as e:
        return JSONResponse({"detail": f"Keycloak error: {e.response.text}"}, e.response.status_code)
    except HTTPException as e:
        return JSONResponse({"detail": e.detail}, e.status_code)


@app.get("/")
async def public_endpoint():
    return {"message": "This is a public endpoint"}


@app.get("/read")
async def protected_endpoint(request: Request):
    return {"message": f"Authenticated client '{request.state.client}' accessed protected data"}
