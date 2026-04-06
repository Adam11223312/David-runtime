stapi import FastAPI, Request, HTTPException, Header
from fastapi.responses import FileResponse
from datetime import datetime, timedelta
from pydantic import BaseModel
from typing import Optional
import re, uuid, unicodedata, time, base64, hmac, hashlib, random, asyncio
import os

# =========================
# APP INIT
# =========================
app = FastAPI(title="David AI – Full System")

# =========================
# CONFIG
# =========================
SECRET_KEY = "DAVID_SUPER_SECRET"
VALID_TOKENS = {"david_rt_fresh1": {"role":"admin", "expires": datetime.utcnow() + timedelta(hours=12)}}
USED_
