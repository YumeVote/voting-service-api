# Voting Service API

Author : Htet Aung Hlaing (Victor)

## Target Requirements

1. Vote Database that stores Vote ID (which will be returned to the user as mentioned in No.3), Vote (which candidate was it (Joe Biden or Donald Trump)), Digital Signature.
2. Vote Blockchain with Maschain with Audit Service enabled that will store the ID and the Hash of a particular vote entry from Vote Database
3. Voting Service API that allows the IoT Machine to vote. When a vote is received, the verification process starts by using a similar way as No.5 in the Context section. (Comparing every public key with the digital signature). If the vote is valid as signed and proved by the digital signature and exposed public keys, the entry is added to the Voting Database. The hash of this particular entry is also added onto Vote Blockchain.

## Solutions

1. Using the ```data-setup.py```, the database system is setup
2. the database has a transaction hash which can be related with the audit record on the blockchain for later purposes
3. ```voting-service-api.py``` exposes three apis to the public
    1. History (allows anybody to see the history with blockchain hashes)
    2. Results (allows anybody to view the latest result)
    3. Vote (allows the user to vote for a particular candidate)

## How To Run
To set things up easily, I have quickly created a Makefile.

1. ```make install```
    Install the necessary python packages
2. ```make setup```
    clean the database and set up a new database
3. ```make```
    install the packages
    starts the api server