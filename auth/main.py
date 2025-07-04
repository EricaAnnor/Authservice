from fastapi import FastAPI
from .auth import auth_routers, protected_router, google_routers
from starlette.middleware.sessions import SessionMiddleware
from fastapi.middleware.cors import CORSMiddleware
import os
from dotenv import load_dotenv

load_dotenv()

app = FastAPI()

# ✅ Add CORSMiddleware first
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000", 
        "http://localhost:8000"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ✅ Add SessionMiddleware separately
app.add_middleware(
    SessionMiddleware,
    secret_key=os.getenv("SESSION_SECRET", "your-secret-key")
)

# ✅ Include routers
app.include_router(auth_routers)
app.include_router(protected_router)
app.include_router(google_routers)

@app.get("/")
def start():
    return {"message": "hey there"}
