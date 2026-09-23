"""
UNCONTROLLED ENVIRONMENT - 3) OPTIMIZED AUTHORIZATION  (report section 5.2.3)

Improvements over authorization.py:
  1. Public keys (JWKS) are CACHED        -> no /certs call per request
     (refreshed automatically if Keycloak rotates its key)
  2. RPT introspection is REMOVED         -> the RPT is a signed JWT, so it is
     verified locally with the cached public key instead
  3. Access token and RPT are CACHED until shortly before they expire
     -> Keycloak is only called again when a token is about to expire
  4. One shared HTTP connection pool      -> no new TCP connection per call
  5. A lock prevents many simultaneous requests from all fetching tokens at once

Report result: default 133.75 ms / 12 exchanges -> optimized 61.36 ms / 6 exchanges
(caching the tokens as well reduces repeated requests even further).

Run:  uvicorn authorization_optimized:app --port 8000
Test: curl http://localhost:8000/read
"""
import asyncio
import time
from contextlib import asynccontextmanager

import httpx
import jwt
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from loguru import logger

import config

EXPIRY_MARGIN = 10  # seconds: renew a token this long before it expires
ISSUER = f"{config.KEYCLOAK_URL}/realms/{config.REALM}"


class KeycloakAuthorizer:
    def __init__(self) -> None:
        self.http = httpx.AsyncClient(timeout=10)
        self.jwks: dict[str, jwt.PyJWK] = {}      # kid -> public key
        self.access_token: tuple[str, float] | None = None  # (token, expires_at)
        self.rpt: tuple[str, dict, float] | None = None     # (token, claims, expires_at)
        self.lock = asyncio.Lock()

    # ---------- public keys (cached) ----------
    async def _load_jwks(self) -> None:
        start = time.perf_counter()
        r = await self.http.get(config.CERTS_URL)
        r.raise_for_status()
        self.jwks = {k["kid"]: jwt.PyJWK(k) for k in r.json()["keys"] if k.get("use") == "sig"}
        logger.info(f"Public keys cached ({(time.perf_counter() - start) * 1000:.2f} ms)")

    async def _verify(self, token: str) -> dict:
        kid = jwt.get_unverified_header(token).get("kid")
        if kid not in self.jwks:          # first use or key rotation -> refresh once
            await self._load_jwks()
        if kid not in self.jwks:
            raise HTTPException(401, "Signing key not found")
        try:
            return jwt.decode(token, self.jwks[kid].key, algorithms=["RS256"],
                              issuer=ISSUER, options={"verify_aud": False})
        except jwt.ExpiredSignatureError:
            raise HTTPException(401, "Token has expired")
        except jwt.InvalidTokenError as e:
            raise HTTPException(401, f"Invalid token: {e}")

    # ---------- access token (cached) ----------
    async def _get_access_token(self) -> str:
        if self.access_token and self.access_token[1] > time.time():
            return self.access_token[0]
        start = time.perf_counter()
        r = await self.http.post(config.TOKEN_URL, data={
            "grant_type": "client_credentials",
            "client_id": config.CLIENT_ID,
            "client_secret": config.CLIENT_SECRET,
        })
        r.raise_for_status()
        token = r.json()["access_token"]
        claims = await self._verify(token)
        self.access_token = (token, claims["exp"] - EXPIRY_MARGIN)
        logger.info(f"Access token RTT: {(time.perf_counter() - start) * 1000:.2f} ms")
        return token

    # ---------- RPT (cached, verified locally, no introspection) ----------
    async def get_rpt(self) -> tuple[str, dict]:
        async with self.lock:
            if self.rpt and self.rpt[2] > time.time():
                return self.rpt[0], self.rpt[1]
            access_token = await self._get_access_token()
            start = time.perf_counter()
            r = await self.http.post(
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
            rpt = r.json()["access_token"]
            claims = await self._verify(rpt)
            self.rpt = (rpt, claims, claims["exp"] - EXPIRY_MARGIN)
            logger.info(f"RPT RTT: {(time.perf_counter() - start) * 1000:.2f} ms")
            return rpt, claims

    async def close(self) -> None:
        await self.http.aclose()


def has_permission(claims: dict, required: str) -> bool:
    resource, _, scope = required.partition("#")
    return any(
        p.get("rsname") == resource and (not scope or scope in p.get("scopes", []))
        for p in claims.get("authorization", {}).get("permissions", [])
    )


authorizer = KeycloakAuthorizer()


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield
    await authorizer.close()


app = FastAPI(title="Uncontrolled - Authorization (optimized)", lifespan=lifespan)


@app.middleware("http")
async def authorize(request: Request, call_next):
    if request.url.path == "/":
        return await call_next(request)
    start = time.perf_counter()
    try:
        rpt, claims = await authorizer.get_rpt()
        if not has_permission(claims, config.PERMISSION):
            raise HTTPException(403, "RPT does not grant the required permission")
        request.state.rpt = rpt
        response = await call_next(request)
        logger.info(f"TOTAL authorization: {(time.perf_counter() - start) * 1000:.2f} ms")
        return response
    except httpx.HTTPStatusError as e:
        return JSONResponse({"detail": f"Keycloak error: {e.response.text}"}, e.response.status_code)
    except httpx.RequestError as e:
        return JSONResponse({"detail": f"Keycloak unreachable: {e}"}, 503)
    except HTTPException as e:
        return JSONResponse({"detail": e.detail}, e.status_code)


@app.get("/")
async def public_endpoint():
    return {"message": "This is a public endpoint"}


@app.get("/read")
async def protected_endpoint(request: Request):
    return {"message": "Confidential data accessed with a valid RPT"}
