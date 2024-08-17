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
    """
    candidate id: the id of the candidate that the citizen is voting for
    voteDigitalSignature: the digital signature of the vote
    identitySignature: the digital signature of the citizen's identity
    """
    candidate_id: int
    vote: str
    voteDigitalSignature: str
    identitySignature: str
    storedIdentitySignature: str

GOVERNMENT_SERVICE_API_HOST=os.getenv("GOVERNMENT_SERVICE_API_HOST")
GOVERNMENT_SERVICE_API_PORT=os.getenv("GOVERNMENT_SERVICE_API_PORT")
GOVERNMENT_SERVICE_API = "http://{}:{}".format(GOVERNMENT_SERVICE_API_HOST, GOVERNMENT_SERVICE_API_PORT)
GOVERNMENT_SERVICE_PUBLIC_KEY_API="{}/keys".format(GOVERNMENT_SERVICE_API)
GOVERNMENT_SERVICE_CITIZEN_VERIFICATION_API="{}/verify".format(GOVERNMENT_SERVICE_API)

MASCHAIN_CLIENT_ID = os.getenv("MASCHAIN_CLIENT_ID")
MASCHAIN_CLIENT_SECRET = os.getenv("MASCHAIN_CLIENT_SECRET")
ORGANIZATION_WALLET_ADDRESS = os.getenv("ORGANIZATION_WALLET_ADDRESS")
VOTING_AUDIT_SMART_CONTRACT_ADDRESS = os.getenv("VOTING_AUDIT_SMART_CONTRACT_ADDRESS")
VOTING_TOKEN_SMART_CONTRACT_ADDRESS = os.getenv("VOTING_TOKEN_SMART_CONTRACT_ADDRESS")
STORED_IDENTITY_ORIGINAL_MESSAGE = os.getenv("STORED_IDENTITY_ORIGINAL_MESSAGE")

headers = {
    "client_id": MASCHAIN_CLIENT_ID,
    "client_secret": MASCHAIN_CLIENT_SECRET,
    "content-type": "application/json"
}

app = FastAPI()

def verify_citizen(digitalIdentitySignature: str):
    verification_response = requests.post(GOVERNMENT_SERVICE_CITIZEN_VERIFICATION_API, params={"digitalIdentitySignature": digitalIdentitySignature})
    print(verification_response.text)
    if verification_response.status_code != 200:
        print("Verification failed")
        return False
    return True

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

def get_candidate_wallet_address(candidate_id):
    conn = sqlite3.connect('assets/voting-system.sql')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT WalletAddress FROM Candidates
        WHERE ID = ?
    ''', (candidate_id,))
    wallet_address = cursor.fetchone()[0]
    conn.close()
    return wallet_address

def get_candidate_name(candidate_id):
    conn = sqlite3.connect('assets/voting-system.sql')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT CandidateName FROM Candidates
        WHERE ID = ?
    ''', (candidate_id,))
    candidate_name = cursor.fetchone()[0]
    conn.close()
    return candidate_name

def add_vote_to_candidate_wallet(wallet_address):
    response = requests.post(
        "https://service-testnet.maschain.com/api/token/mint",
        headers=headers,
        params={
            "wallet_address": ORGANIZATION_WALLET_ADDRESS,
            "to": wallet_address,
            "amount": 1,
            "contract_address": VOTING_TOKEN_SMART_CONTRACT_ADDRESS,
            "callback_url": "http://gmail.com"
        }
    )
    print(response.json())
    return response.json()["result"]["transactionHash"]

@app.get("/")
def read_root():
    return "Voting Service API is running properly"

@app.get("/candidates")
def candidates():
    """
    This endpoint is used to get the list of candidates that citizens can vote for
    1. It fetches all the candidates from the database
    2. It returns the candidates as a list of dictionaries
    """
    conn = sqlite3.connect('assets/candidates.sql')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT ID, CandidateName FROM Candidates
    ''')
    candidates = cursor.fetchall()
    conn.close()
    return candidates

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
        SELECT CandidateName, WalletAddress FROM Candidates
    ''')
    candidates = cursor.fetchall()
    conn.close()
    voting_result = []

    for candidate in candidates:
        balance = requests.post(
            "https://service-testnet.maschain.com/api/token/balance", 
            headers=headers, 
            params={
                "wallet_address": candidate[1], 
                "contract_address": VOTING_TOKEN_SMART_CONTRACT_ADDRESS}
            )

        voting_result.append(
            {
                "CandidateName": candidate[0],
                "Votes": balance.json()["result"]
            }
        )
    return voting_result

@app.post("/vote")
async def vote(vote: Vote):
    """
    This endpoint is used to cast a vote
    1. It receives the vote and signature from the client
    2. It verifies the signature with all the public keys exposed by the government
    3. If the signature is verified, a NFT is minted and the vote is a
    4. If the signature is not verified, the vote is not added to the database and an error response is returned
    """
    response = requests.get(GOVERNMENT_SERVICE_PUBLIC_KEY_API)
    public_keys = ast.literal_eval(response.text)
    conn = sqlite3.connect('assets/voting-system.sql')
    cursor = conn.cursor()
    try:

        if not verify_citizen(vote.identitySignature):
            # ask the government's service to verify the citizen
            raise HTTPException(status_code=403, detail="Invalid Citizen")
        
        for public_key in public_keys:
            # check if the person who votes is a valid citizen or not
            # the voting system itself check if the vote has been signed by the citizen or not
            if not verify_signature(public_key, vote.storedIdentitySignature, STORED_IDENTITY_ORIGINAL_MESSAGE):
                print(STORED_IDENTITY_ORIGINAL_MESSAGE)
                continue

            if not verify_signature(public_key, vote.voteDigitalSignature, vote.vote):
                raise HTTPException(status_code=403, detail="Invalid Vote")

            if not verify_signature(public_key, vote.voteDigitalSignature, get_candidate_name(vote.candidate_id)):
                raise HTTPException(status_code=403, detail="Invalid Candidate")

            cursor.execute('''
                INSERT INTO Votes (Vote, VoteDigitalSignature, IdentityDigitalSignature)
                VALUES (?, ?, ?)
            ''', (vote.vote, vote.voteDigitalSignature, vote.storedIdentitySignature))
            conn.commit()

            vote_id = cursor.lastrowid
            hash_of_vote = hashlib.sha256((str(vote_id)+","+vote.vote+","+ vote.storedIdentitySignature + "," + vote.identitySignature).encode()).hexdigest()
            vote_transaction_hash = add_vote_to_candidate_wallet(get_candidate_wallet_address(vote.candidate_id))

            metaData = {
                "vote_transaction_hash": vote_transaction_hash,
                "hash_of_vote": hash_of_vote
            }

            # Make the API request with the JSON string
            vote_audit_response = requests.post(
                headers=headers,
                url="https://service-testnet.maschain.com/api/audit/audit",
                params={
                    "wallet_address": ORGANIZATION_WALLET_ADDRESS,
                    "contract_address": VOTING_AUDIT_SMART_CONTRACT_ADDRESS,
                    "metadata": metaData,
                    "callback_url": "http://gmail.com"
                }
            )

            vote_audit_json_object = vote_audit_response.json()
            auditTransactionHash = vote_audit_json_object["result"]["transactionHash"]

            cursor.execute('''
                UPDATE Votes
                SET VoteTransactionHash = ?, AuditTransactionHash = ?
                WHERE ID = ?
            ''', (vote_transaction_hash, auditTransactionHash ,vote_id))
            print(vote_audit_json_object)

            conn.commit()

            return str(vote_id)
        # if after looping every single public key, the signature is not verified
        # that means the citizen is invalid
        print("Loop cannot find")
        raise HTTPException(status_code=403, detail="Invalid Citizen")
    except sqlite3.IntegrityError as e:
        conn.rollback()
        raise HTTPException(status_code=403, detail="Citizen already voted")
    finally:
        conn.close()

