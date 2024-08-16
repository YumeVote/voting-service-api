from http.client import HTTPResponse
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
from dotenv import load_dotenv
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
import base64

import os
import requests
import ast
import sqlite3
import hashlib

load_dotenv()

class Vote(BaseModel):
    vote: str
    signature: str

GOVERNMENT_SERVICE_API_HOST=os.getenv("GOVERNMENT_SERVICE_API_HOST")
GOVERNMENT_SERVICE_API_PORT=os.getenv("GOVERNMENT_SERVICE_API_PORT")
GOVERNMENT_SERVICE_PUBLIC_KEY_API="http://{}:{}/keys".format(GOVERNMENT_SERVICE_API_HOST, GOVERNMENT_SERVICE_API_PORT)

MASCHAIN_CLIENT_ID = os.getenv("MASCHAIN_CLIENT_ID")
MASCHAIN_CLIENT_SECRET = os.getenv("MASCHAIN_CLIENT_SECRET")
ORGANIZATION_WALLET_ADDRESS = os.getenv("ORGANIZATION_WALLET_ADDRESS")
VOTING_AUDIT_SMART_CONTRACT_ADDRESS = os.getenv("VOTING_AUDIT_SMART_CONTRACT_ADDRESS")

headers = {
    "client_id": MASCHAIN_CLIENT_ID,
    "client_secret": MASCHAIN_CLIENT_SECRET,
    "content-type": "application/json"
}

app = FastAPI()

def verify_signature(public_key_pem, signature, message):
    # Load the public key
    public_key = serialization.load_pem_public_key(public_key_pem.encode(), serialization.Encoding.PEM)
    try:
        print(public_key)
        # Verify the signature
        public_key.verify(
            base64.b64decode(signature),
            message.encode(),
            padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(f"Verification failed: {e}")
        return False

@app.get("/")
def read_root():
    return "Voting Service API is running properly"

@app.get("/history")
async def history():
    """
    This endpoint is used to get the history of votes
    1. It fetches all the votes from the database
    2. It returns the votes as a list of dictionaries
    """
    conn = sqlite3.connect('assets/voting-system.sql')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT * FROM Votes
    ''')
    votes = cursor.fetchall()
    conn.close()

    audit_trail_history_response = requests.get(
        headers=headers,
        url="https://service-testnet.maschain.com/api/audit/audit"
    )

    audit_trail_history_response_json = audit_trail_history_response.json()

    audit_history = []
    for i, vote in enumerate(votes):
        for audit_trail in audit_trail_history_response_json["result"]:
            print(vote[3], audit_trail["transactionHash"])
            if vote[3] == audit_trail["transactionHash"]:
                audit_history.append({
                    "ID": vote[0],
                    "Vote": vote[1],
                    "Signature": vote[2],
                    "TransactionHash": vote[3],
                    "Hash": audit_trail["metadata"]
                })
                break
    return audit_history

@app.get("/results")
def results():
    """
    This endpoint is used to get the result of the election
    1. It fetches all the votes from the database
    2. It counts the votes and returns the result as a dictionary
    """
    conn = sqlite3.connect('assets/voting-system.sql')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT Vote, COUNT(Vote) FROM Votes
        GROUP BY Vote
    ''')
    votes = cursor.fetchall()
    conn.close()

    result = {}
    for vote in votes:
        result[vote[0]] = vote[1]
    return result

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
    conn = sqlite3.connect('assets/voting-system.sql')
    cursor = conn.cursor()
    try:
        for public_key in public_keys:
            if verify_signature(public_key, vote.signature, vote.vote):
                cursor.execute('''
                    INSERT INTO Votes (Vote, Signature)
                    VALUES (?, ?)
                ''', (vote.vote, vote.signature))
                conn.commit()

                vote_id = cursor.lastrowid
                hash_of_vote = hashlib.sha256((str(vote_id)+","+vote.vote+","+vote.signature).encode()).hexdigest()

                # Make the API request with the JSON string
                vote_audit_response = requests.post(
                    headers=headers,
                    url="https://service-testnet.maschain.com/api/audit/audit",
                    params={
                        "wallet_address": ORGANIZATION_WALLET_ADDRESS,
                        "contract_address": VOTING_AUDIT_SMART_CONTRACT_ADDRESS,
                        "metadata": hash_of_vote,
                        "callback_url": "http://gmail.com"
                    }
                )

                vote_audit_json_object = vote_audit_response.json()
                transactionHash = vote_audit_json_object["result"]["transactionHash"]

                cursor.execute('''
                    UPDATE Votes
                    SET TransactionHash = ?
                    WHERE ID = ?
                ''', (transactionHash, vote_id))
                print(vote_audit_json_object)

                conn.commit()

                return str(vote_id)
        # if after looping every single public key, the signature is not verified
        # that means the citizen is invalid
        raise HTTPException(status_code=403, detail="Invalid Citizen")
    except sqlite3.IntegrityError as e:
        conn.rollback()
        raise HTTPException(status_code=403, detail="Citizen already voted")
    finally:
        conn.close()

