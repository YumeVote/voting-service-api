"""
This script does pre-defined data related operations
1. Create a database
2. Create the Votes data table
"""

import sqlite3
import os

if not os.path.exists('assets'):
    os.makedirs('assets')

conn = sqlite3.connect('assets/voting-system.sql')
cursor = conn.cursor()

# Create the Citizen table
cursor.execute('''
    CREATE TABLE Votes (
        ID INTEGER PRIMARY KEY AUTOINCREMENT,
        Vote TEXT,
        Signature TEXT UNIQUE,
        TransactionHash TEXT
    )
''')

conn.commit()
conn.close()