from fastapi import APIRouter, Depends, HTTPException, status,Response,Request
from fastapi.security import OAuth2PasswordRequestForm,OAuth2PasswordBearer
from typing import Annotated
import jwt
from passlib.context import CryptContext
from .database import get_connection, return_connection
from .models import User, UserCreate,Token,RefreshRequest
import logging
import os 
from dotenv import load_dotenv
from datetime import timedelta,datetime,timezone
import re
from .oauth import oauth
import json

load_dotenv()

auth_routers = APIRouter(prefix="/api/v1/auth", tags=["Authentication endpoints"])

protected_router = APIRouter(prefix="/api/v1/protected", tags=["Protected endpoints"])

google_routers = APIRouter(prefix="/api/v1/auth/google",tags=["Login with Google endpoints"])

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/v1/auth/login")

logger = logging.getLogger(__name__)

def hash_password(password):
    return pwd_context.hash(password)  

def verify_password(plain_password,hashed_password):
    return pwd_context.verify(plain_password,hashed_password)

def is_email(value: str) -> bool:
    return "@" in value and re.match(r"[^@]+@[^@]+\.[^@]+", value)



def verify_user(username_or_email, plain_password, flag):
    print("verify_user called with:", username_or_email, "flag:", flag)

    connection = None
    try:
        connection = get_connection()
        cursor = connection.cursor()

        if flag:
            print("Checking by username...")
            cursor.execute("SELECT password FROM users WHERE username = %s", (username_or_email,))
        else:
            print("Checking by email...")
            cursor.execute("SELECT password FROM users WHERE email = %s", (username_or_email,))
            print("email in use") 

        result = cursor.fetchone()
        cursor.close()

        if not result:
            print("No user found.")
            return False

        print("Fetched user:", result)

        hashed_password = result["password"]
        return verify_password(plain_password, hashed_password)

    except Exception as e:
        print("Error:", e)
        if connection:
            connection.rollback()
        return False
    finally:
        if connection:
            return_connection(connection)



def create_access_token(data:dict,expire_time: timedelta|None = None):
    encode_data = data.copy()

    if expire_time:
        expire = datetime.now(timezone.utc) + timedelta(minutes= int(os.getenv("ACCESSEXPIRETIME",15)))

    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)

    encode_data.update({"exp":expire})

    encoded_jwt = jwt.encode(encode_data, os.getenv("SECRET_KEY"), algorithm=os.getenv("ALGORITHM"))
    return encoded_jwt
     
def create_refresh_token(data:dict,expire_time: timedelta|None = None):
    encode_data = data.copy()

    if expire_time:
        expire = datetime.now(timezone.utc) + timedelta(days = int(os.getenv("ACCESSEXPIRETIME",7)))

    else:
        expire = datetime.now(timezone.utc) + timedelta(days = 7)

    encode_data.update({"exp":expire})

    encoded_jwt = jwt.encode(encode_data, os.getenv("SECRET_KEY"), algorithm=os.getenv("ALGORITHM"))
    return encoded_jwt      


@auth_routers.post("/register", response_model=User)
def register_user(data: UserCreate):
    connection = None
    try:
        connection = get_connection()
        cursor = connection.cursor()

        cursor.execute("SELECT * FROM users WHERE email = %s", (data.email,))
        if cursor.fetchone():
            raise HTTPException(status_code=400, detail="Email already in use")

        cursor.execute("SELECT * FROM users WHERE username = %s", (data.username,))
        if cursor.fetchone():
            raise HTTPException(status_code=400, detail="Username already in use")

        cursor.execute("SELECT id FROM company WHERE name = %s", (data.company,))
        company_row = cursor.fetchone()
        if not company_row:
            raise HTTPException(status_code=400, detail="Company does not exist")

        company_id = company_row['id']

        cur_password = hash_password(data.password)

        cursor.execute(
            """
            INSERT INTO users (
                email, username, firstname, lastname, role, password, company_id
            ) VALUES (%s, %s, %s, %s, %s, %s, %s)
            RETURNING id
            """,
            (
                data.email,
                data.username,
                data.firstname,
                data.lastname,
                data.role,
                cur_password,
                company_id
            )
        )

        user_id = cursor.fetchone()['id']
        connection.commit()

        return User(
            id=user_id,
            email=data.email,
            username=data.username,
            firstname=data.firstname,
            lastname=data.lastname,
            role=data.role,
            company=data.company
        )

    except Exception as e:
        if connection:
            connection.rollback()
        logger.exception("An error occurred while registering the user")  
        raise HTTPException(status_code=500, detail=str(e))  
    finally:
        if connection:
            return_connection(connection)

@auth_routers.post("/login")
def login(response: Response, data: Annotated[OAuth2PasswordRequestForm, Depends()]) -> Token:
    print("checkkkkk")
    if is_email(data.username):
        check = verify_user(data.username, data.password, False)
    else:
        check = verify_user(data.username, data.password, True)

    if not check:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = create_access_token(
        {"sub": data.username},
        timedelta(minutes=int(os.getenv("ACCESSEXPIRETIME", 15)))
    )
    refresh_token = create_refresh_token(
        {"sub": data.username},
        timedelta(days=int(os.getenv("REFRESHEXPIRETIME", 7)))
    )

    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=True,
        samesite="Lax",
        max_age=60 * 60 * 24 * 7
    )

    return Token(
        access_token=access_token, 
        access_type="Bearer",
        refresh_token=refresh_token
        )

@auth_routers.post("/refresh")
def refresh(request:Request,body:RefreshRequest = None):
    try:
        refresh_token = request.cookies.get("refresh_token")
        
        if not refresh_token and body:
            refresh_token = body.refresh_token
        elif not refresh_token and not body:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="refresh token missing",
                headers={"WWW-Authenticate": "Bearer"},
            )
        

        user = jwt.decode(refresh_token,os.getenv("SECRET_KEY"),os.getenv("ALGORITHM"))

        username = user.get("sub")

        if not username:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="refresh token not valid",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        access_token = create_access_token(
            {"sub": username},
            timedelta(minutes=int(os.getenv("ACCESSEXPIRETIME", 15)))
        )

        return Token(access_token=access_token, access_type="Bearer",refresh_token=refresh_token)

    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Refresh token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    

@auth_routers.get("/logout")
def logout(response:Response):

    response.delete_cookie("refresh_token")

    return {"message":"User logged out"}



@protected_router.get("/me")
def profile(token: Annotated[str, Depends(oauth2_scheme)]):
    connection = None
    try:
        print("started")
        payload = jwt.decode(token, os.getenv("SECRET_KEY"), algorithms=[os.getenv("ALGORITHM")])
        userName = payload.get('sub')
        print("Decoded username:", userName)

        if not userName:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Access token invalid")

        connection = get_connection()
        cursor = connection.cursor()

        cursor.execute("SELECT * FROM users WHERE username = %s", (userName,))
        data = cursor.fetchone()
        print("Fetched user data:", data)

        if not data:
            raise HTTPException(status_code=404, detail="User not found")
        
        print(data)
        cur_id = data["company_id"]
        print(cur_id)
        cursor.execute("SELECT name FROM company WHERE id = %s",(cur_id,))
        company_name = cursor.fetchone()
    
        return User(
            id=data["id"],
            email=data["email"],
            username=data["username"],
            firstname=data["firstname"],
            lastname=data["lastname"],
            role=data["role"],
            company=company_name["name"]
        )

    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")
    finally:
        if connection:
            return_connection(connection)


@google_routers.get("/login")
async def login_google(request:Request):
    redirect_uri = os.getenv("GOOGLE_REDIRECT_URI")

    return await oauth.google.authorize_redirect(request,redirect_uri)

@google_routers.get("/callback")
async def google_callback(request: Request,response:Response):
    try:
        token = await oauth.google.authorize_access_token(request)
        print(token)
        try:
            user_info = await oauth.google.parse_id_token(request, token)
        except Exception:
            user_info = await oauth.google.userinfo(token=token)
        print("Google user:", user_info)

        

        connection = get_connection()
        cursor = connection.cursor()
        cur_email = user_info["email"]
        cursor.execute("SELECT username FROM users WHERE email = %s",(cur_email,))

        cur = cursor.fetchone()

        user = {
            "email": user_info["email"],
            "name": user_info["name"],
            "picture": user_info["picture"]
        }

        if not cur:
            response.set_cookie(
                key="user_details",
                value=json.dumps(user),
                httponly=True,
                secure=True,
                samesite="Lax",
                max_age=60 * 60 * 24 * 7
            )

            return user
                
        cur_user = cur["username"]
        access_token = create_access_token(
            {"sub": cur_user},
            timedelta(minutes=int(os.getenv("ACCESSEXPIRETIME", 15)))
        )
        refresh_token = create_refresh_token(
            {"sub": cur_user},
            timedelta(days=int(os.getenv("REFRESHEXPIRETIME", 7))))
        
        return Token(access_token=access_token, access_type="Bearer",refresh_token=refresh_token)

    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Google login failed: {str(e)}")
