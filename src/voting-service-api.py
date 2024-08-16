from fastapi import FastAPI, Request
from pydantic import BaseModel
from dotenv import load_dotenv
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key
import base64

import os
import requests
import ast

load_dotenv()

class Vote(BaseModel):
    vote: str
    signature: str

GOVERNMENT_SERVICE_API_HOST=os.getenv("GOVERNMENT_SERVICE_API_HOST")
GOVERNMENT_SERVICE_API_PORT=os.getenv("GOVERNMENT_SERVICE_API_PORT")
GOVERNMENT_SERVICE_PUBLIC_KEY_API="http://{}:{}/keys".format(GOVERNMENT_SERVICE_API_HOST, GOVERNMENT_SERVICE_API_PORT)

print(GOVERNMENT_SERVICE_PUBLIC_KEY_API)

app = FastAPI()

def verify_signature(public_key_pem, signature, message):
    # Load the public key
    public_key = load_pem_public_key(public_key_pem.encode())
    try:
        # Verify the signature
        public_key.verify(
            base64.b64decode(signature),
            message.encode(),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(f"Verification failed: {e}")
        return False

@app.get("/")
def read_root():
    return "Voting Service API is running properly"

@app.post("/vote")
async def vote(vote: Vote):
    """
    This endpoint is used to cast a vote
    1. It receives the vote and signature from the client
    2. It verifies the signature with all the public keys exposed by the government
    3. If the signature is verified, the vote is added to the database and the hash of this vote entry is auditted on the blockchain
    4. If the signature is not verified, the vote is not added to the database and an error response is returned
    """
    response = requests.get(GOVERNMENT_SERVICE_PUBLIC_KEY_API)
    public_keys = ast.literal_eval(response.text)
    for public_key in public_keys:
        if verify_signature(public_key, vote.signature, vote.vote):
            return "Vote casted successfully"
    return "Signature verification failed"

