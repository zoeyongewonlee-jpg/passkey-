from fastapi import APIRouter, HTTPException, Request
from fido2.server import Fido2Server
from fido2.webauthn import PublicKeyCredentialRpEntity
from fido2.utils import websafe_encode
from typing import Dict

router = APIRouter()

# Setup Relying Party (your site)
rp = PublicKeyCredentialRpEntity(id="localhost", name="My App")
server = Fido2Server(rp)

# Store users & credentials in memory for demo (use DB in production!)
USERS: Dict[str, Dict] = {}

# Step 1: Registration options
@router.post("/register/options")
async def register_options(request: Request):
    data = await request.json()
    username = data.get("username")
    if not username:
        raise HTTPException(status_code=400, detail="Username required")

    user = USERS.setdefault(username, {"id": username.encode(), "credentials": []})

    registration_data, state = server.register_begin(
        {"id": user["id"], "name": username, "displayName": username},
        user["credentials"],
        user_verification="discouraged",
    )

    user["state"] = state
    return registration_data

# Step 2: Verify Registration
@router.post("/register/verify")
async def register_verify(request: Request):
    data = await request.json()
    username = data.get("username")
    user = USERS.get(username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    credential = server.register_complete(user["state"], data)
    user["credentials"].append(credential)
    return {"status": "ok"}
