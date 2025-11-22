from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import firebase_admin
from firebase_admin import credentials, firestore
from jose import jwt
import time
import os
import uvicorn

# ========================
# CONFIG
# ========================
FIREBASE_KEYFILE = "firebase-key.json"
JWT_PRIVATE_KEY_FILE = "privkey.pem"
JWT_PUBLIC_KEY_FILE = "pubkey.pem"
ALG = "RS256"

# ========================
# Load Firebase
# ========================
if not os.path.exists(FIREBASE_KEYFILE):
    raise RuntimeError("Missing firebase-key.json in server folder")

cred = credentials.Certificate(FIREBASE_KEYFILE)
firebase_admin.initialize_app(cred)
db = firestore.client()

# ========================
# Load RSA keys
# ========================
with open(JWT_PRIVATE_KEY_FILE, "rb") as f:
    PRIVATE_KEY = f.read()

with open(JWT_PUBLIC_KEY_FILE, "rb") as f:
    PUBLIC_KEY = f.read()

# ========================
# FastAPI App
# ========================
app = FastAPI(title="License Activation Server")

# Request body models
class ActivateReq(BaseModel):
    license: str
    hwid: str

class DeactivateReq(BaseModel):
    license: str
    hwid: str


# ========================
# ACTIVATE ENDPOINT
# ========================
@app.post("/activate")
def activate(req: ActivateReq):

    doc_ref = db.collection("licenses").document(req.license)
    doc = doc_ref.get()

    if not doc.exists:
        raise HTTPException(status_code=404, detail="License not found")

    data = doc.to_dict()

    # FIRST ACTIVATION
    if not data.get("active", False):
        doc_ref.update({
            "active": True,
            "hwid": req.hwid
        })
    else:
        # Already activated before
        if data.get("hwid") != req.hwid:
            raise HTTPException(status_code=403, detail="License already used on another device")

    # Generate signed token
    payload = {
        "license": req.license,
        "hwid": req.hwid,
        "iat": int(time.time())
    }

    token = jwt.encode(payload, PRIVATE_KEY, algorithm=ALG)

    return {
        "token": token,
        "public_key": PUBLIC_KEY.decode()
    }


# ========================
# DEACTIVATE ENDPOINT
# ========================
@app.post("/deactivate")
def deactivate(req: DeactivateReq):

    doc_ref = db.collection("licenses").document(req.license)
    doc = doc_ref.get()

    if not doc.exists:
        raise HTTPException(status_code=404, detail="License not found")

    data = doc.to_dict()

    if data.get("hwid") != req.hwid:
        raise HTTPException(status_code=403, detail="HWID mismatch")

    doc_ref.update({
        "active": False,
        "hwid": ""
    })

    return {"status": "ok"}


# ========================
# RUN ON RAILWAY
# ========================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 3000))  # Railway injects PORT
    uvicorn.run("server:app", host="0.0.0.0", port=port)
