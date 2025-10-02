from typing import Union
from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
import sqlalchemy
from data.db_session import global_init, create_session
from pydantic import BaseModel
from data import db_session
from sqlalchemy.orm import Session
from argon2 import PasswordHasher
from data.userlogin import UserLogin
from passlib.context import CryptContext
from data.Users import Users_B, Users, UserRead

app = FastAPI()
global_init('db.db')
pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")


def get_db():
    db = db_session.create_session()
    try:
        yield db
    finally:
        db.close()


app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # адрес React
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.post("/api/register", response_model=UserRead)
async def reg_user(item: Users_B, db_sess: Session = Depends(get_db)):
    if db_sess.query(Users).filter(Users.email == item.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")
    try:
        new_user = Users(
            name=item.name,
            email=item.email,
            password=hashed_password(item.password)
        )
        db_sess.add(new_user)
        db_sess.commit()
        db_sess.refresh(new_user)
    except sqlalchemy.exc.StatementError:
        raise HTTPException(status_code=400, error='Bad request')
    else:
        return new_user


@app.post("/api/login", response_model=UserRead)
async def login_user(user: UserLogin, db_sess: Session = Depends(get_db)):
    db_user = db_sess.query(Users).filter(Users.email == user.email).first()
    if not db_user:
        raise HTTPException(status_code=400, detail="Invalid email or password")
    if not verify_password(user.password, db_user.password):
        raise HTTPException(status_code=400, detail="Invalid email or password")
    return db_user


def hashed_password(password):
    ph = PasswordHasher()
    return ph.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)
