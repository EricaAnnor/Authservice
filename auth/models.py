from pydantic import BaseModel,UUID4,EmailStr

class UserCreate(BaseModel):
    email:EmailStr
    username:str
    password:str
    firstname:str
    lastname:str
    role:str
    company:str


class User(BaseModel):
    id: UUID4
    email:EmailStr
    username:str
    firstname:str
    lastname:str
    role:str
    company:str

    


class Company(BaseModel):
    id:UUID4
    name:str


class Token(BaseModel):
    access_token:str
    access_type:str
    refresh_token:str

class RefreshRequest(BaseModel):
    refresh_token: str

