from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel
from typing import Optional, Dict, Any
import json
import os
import time
import hmac
import hashlib
import base64

app = FastAPI()

API_KEY = os.getenv("DAVID_API_KEY", "change_me_now")
SIGNING_SECRET = os.getenv("DAVID_SIGNING_SECRET", "change_me_signing_secret_now")

# In-memory replay protection for testing
USED_NONCES = set()
USED_EXECUTION_TOKENS = set()


class Enforce
