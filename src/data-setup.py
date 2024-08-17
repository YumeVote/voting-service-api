"""
This script does pre-defined data related operations
1. Create a database
2. Create the candidates table
3. Add 2 to 3 candidates to the candidates table
"""

from dotenv import load_dotenv

import sqlite3
import os
import requests

load_dotenv()

if not os.path.exists('assets'):
    os.makedirs('assets')

MASCHAIN_CLIENT_ID = os.getenv("MASCHAIN_CLIENT_ID")
MASCHAIN_CLIENT_SECRET = os.getenv("MASCHAIN_CLIENT_SECRET")
ORGANIZATION_WALLET_ADDRESS = os.getenv("ORGANIZATION_WALLET_ADDRESS")
VOTING_AUDIT_SMART_CONTRACT_ADDRESS = os.getenv("VOTING_AUDIT_SMART_CONTRACT_ADDRESS")

headers = {
    "client_id": MASCHAIN_CLIENT_ID,
    "client_secret": MASCHAIN_CLIENT_SECRET,
    "content-type": "application/json"
}

conn = sqlite3.connect('assets/voting-system.sql')
cursor = conn.cursor()

# Create the Candidates table
cursor.execute('''
    CREATE TABLE Candidates (
        ID INTEGER PRIMARY KEY AUTOINCREMENT,
        CandidateName TEXT,
        IC Text UNIQUE,
        Email Text UNIQUE,
        WalletAddress TEXT UNIQUE
    )
''')

candidate_1_name = "Donald Trump"
candidate_1_IC = "123456-12-1234"
candidate_1_email = "candidate1@somemail.com"

candidate_1_wallet_creation_response = requests.post(
        "https://service-testnet.maschain.com/api/wallet/create-user", 
        headers=headers,
        params={
            "name": candidate_1_name,
            "email": candidate_1_email,
            "ic": candidate_1_IC
        }
    )

candidate_1_wallet_address_response_object = candidate_1_wallet_creation_response.json()
candidate_1_wallet_address = candidate_1_wallet_address_response_object["result"]["wallet"]["wallet_address"]

cursor.execute('''
    INSERT INTO Candidates (CandidateName, IC, Email, WalletAddress)
    VALUES (?, ?, ?, ?)
''', (candidate_1_name, candidate_1_IC, candidate_1_email, candidate_1_wallet_address))

candidate_2_name = "Joe Biden"
candidate_2_IC = "123456-12-4313"
candidate_2_email = "candidate2@somemail.com"

candidate_2_wallet_creation_response = requests.post(
        "https://service-testnet.maschain.com/api/wallet/create-user", 
        headers=headers,
        params={
            "name": candidate_2_name,
            "email": candidate_2_email,
            "ic": candidate_2_IC
        }
    )

candidate_2_wallet_address_response_object = candidate_2_wallet_creation_response.json()
candidate_2_wallet_address = candidate_2_wallet_address_response_object["result"]["wallet"]["wallet_address"]

cursor.execute('''
    INSERT INTO Candidates (CandidateName, IC, Email, WalletAddress)
    VALUES (?, ?, ?, ?)
''', (candidate_2_name, candidate_2_IC, candidate_2_email, candidate_2_wallet_address))

conn.commit()

# Create the Vote table
cursor.execute('''
    CREATE TABLE Votes (
        ID INTEGER PRIMARY KEY AUTOINCREMENT,
        Vote TEXT,
        VoteDigitalSignature TEXT UNIQUE,
        IdentityDigitalSignature TEXT UNIQUE,
        VoteTransactionHash Text,
        AuditTransactionHash Text
    )
''')

conn.commit()
conn.close()