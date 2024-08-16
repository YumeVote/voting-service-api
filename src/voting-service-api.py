from fastapi import FastAPI

import os
import requests

app = FastAPI()

@app.get("/")
def read_root():
    return "Voting Service API is running properly"