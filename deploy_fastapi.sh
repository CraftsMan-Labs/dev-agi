#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

# Define project directory
PROJECT_DIR="fastapi_project"

# Create project directory
mkdir -p $PROJECT_DIR
cd $PROJECT_DIR

# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Create requirements.txt
cat <<EOL > requirements.txt
fastapi
uvicorn
sqlalchemy
pydantic
passlib[bcrypt]
python-jose
EOL

# Install dependencies
pip install -r requirements.txt

# Create main.py
cat <<EOL > main.py
from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy.orm import Session
from database import SessionLocal, engine, Base
from models import User, Prompt
from schemas import UserCreate, UserLogin, UserResponse, PromptCreate, PromptUpdate, PromptResponse
from security import create_access_token, get_current_user, verify_password, get_password_hash

app = FastAPI()

Base.metadata.create_all(bind=engine)

# Dependency to get DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# User Authentication Endpoints
@app.post("/auth/signup", response_model=UserResponse)
def signup(user: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.username == user.username).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    hashed_password = get_password_hash(user.password)
    db_user = User(username=user.username, email=user.email, hashed_password=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

@app.post("/auth/login")
def login(user: UserLogin, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.username == user.username).first()
    if not db_user or not verify_password(user.password, db_user.hashed_password):
        raise HTTPException(status_code=400, detail="Invalid credentials")
    access_token = create_access_token(data={"sub": db_user.username})
    return {"access_token": access_token, "token_type": "bearer"}

# Prompt Endpoints
@app.post("/prompts", response_model=PromptResponse)
def create_prompt(prompt: PromptCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    db_prompt = Prompt(prompt_text=prompt.prompt_text, owner=current_user)
    db.add(db_prompt)
    db.commit()
    db.refresh(db_prompt)
    return db_prompt

@app.get("/prompts/{id}", response_model=PromptResponse)
def read_prompt(id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    db_prompt = db.query(Prompt).filter(Prompt.id == id, Prompt.user_id == current_user.id).first()
    if db_prompt is None:
        raise HTTPException(status_code=404, detail="Prompt not found")
    return db_prompt

@app.put("/prompts/{id}", response_model=PromptResponse)
def update_prompt(id: int, prompt: PromptUpdate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    db_prompt = db.query(Prompt).filter(Prompt.id == id, Prompt.user_id == current_user.id).first()
    if db_prompt is None:
        raise HTTPException(status_code=404, detail="Prompt not found")
    db_prompt.prompt_text = prompt.prompt_text
    db.commit()
    db.refresh(db_prompt)
    return db_prompt

@app.delete("/prompts/{id}")
def delete_prompt(id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    db_prompt = db.query(Prompt).filter(Prompt.id == id, Prompt.user_id == current_user.id).first()
    if db_prompt is None:
        raise HTTPException(status_code=404, detail="Prompt not found")
    db.delete(db_prompt)
    db.commit()
    return {"detail": "Prompt deleted"}

@app.get("/prompts", response_model=List[PromptResponse])
def list_prompts(skip: int = 0, limit: int = 10, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    prompts = db.query(Prompt).filter(Prompt.user_id == current_user.id).offset(skip).limit(limit).all()
    return prompts
EOL

# Create models.py
cat <<EOL > models.py
from sqlalchemy import Column, Integer, String, ForeignKey, DateTime
from sqlalchemy.orm import relationship
from datetime import datetime
from database import Base

class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    prompts = relationship("Prompt", back_populates="owner")

class Prompt(Base):
    __tablename__ = 'prompts'

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    prompt_text = Column(String, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    owner = relationship("User", back_populates="prompts")
EOL

# Create database.py
cat <<EOL > database.py
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"

engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()
EOL

# Create schemas.py
cat <<EOL > schemas.py
from pydantic import BaseModel, EmailStr
from datetime import datetime

class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str

class UserLogin(BaseModel):
    username: str
    password: str

class UserResponse(BaseModel):
    id: int
    username: str
    email: EmailStr

    class Config:
        orm_mode = True

class PromptCreate(BaseModel):
    prompt_text: str

class PromptUpdate(BaseModel):
    prompt_text: str

class PromptResponse(BaseModel):
    id: int
    user_id: int
    prompt_text: str
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True
EOL

# Create security.py
cat <<EOL > security.py
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from database import SessionLocal
from models import User

SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_current_user(db: Session = Depends(SessionLocal), token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise credentials_exception
    return user
EOL