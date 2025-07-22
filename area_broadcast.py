from datetime import datetime, timedelta, timezone
from typing import Annotated

import jwt
from fastapi import Depends, FastAPI, HTTPException, Query, Form, status
from sqlmodel import Field, Session, SQLModel, create_engine, select
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from jwt.exceptions import InvalidTokenError
from passlib.context import CryptContext
from pydantic import BaseModel

# to get a string like this run:
# openssl rand -hex 32
SECRET_KEY = "557e8c92fd9bc8ff344b19d58b4db88bba40f047bddbfb3158810ec54620d641"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# 認証関係のオブジェクト
class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: str | None = None

# 登録関連のオブジェクト
class InputUser(BaseModel):
    email: str
    displayname: str
    picture: str
    password: str
    isadmin: int

class InputBroadcastProgram(BaseModel):
    title: str
    url: str
    latitude: int
    longitude: int
    floor: int
    year: int
    month: int
    day: int
    hour: int
    price: int
    btname: str
    broadcastcode: str

class BulkInputBroadcastProgram(BaseModel):
    streamer: int
    title: str
    url: str
    latitude: int
    longitude: int
    floor: int
    year: int
    month: int
    day: int
    hour: int
    price: int
    btname: str
    broadcastcode: str

class OutputBroadcastProgram(BaseModel):
    id: int | None = Field(default=None)
    streamername: str | None = Field(default=None)
    streamerpicture: str | None = Field(default=None)
    title: str | None = Field(default=None)
    url: str | None = Field(default=None)
    latitude: int | None = Field(default=None)
    longitude: int | None = Field(default=None)
    floor: int | None = Field(default=None)
    year: int | None = Field(default=None)
    month: int | None = Field(default=None)
    day: int | None = Field(default=None)
    hour: int | None = Field(default=None)
    price: int | None = Field(default=None)
    btname: str | None = Field(default=None)
    rights: str | None = Field(default=None)

class ApproveData(BaseModel):
    id: int

class ProgramSearchData(BaseModel):
    latitude: int | None = Field(default=None)
    longitude: int | None = Field(default=None)
    floor: int | None = Field(default=None)
    year: int | None = Field(default=None)
    month: int | None = Field(default=None)
    day: int | None = Field(default=None)
    hour: int | None = Field(default=None)
    btname: str | None = Field(default=None)
    approval: int | None = Field(default=None)

class BuyData(BaseModel):
    id: int

# DBに保存するオブジェクト
class User(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    email: str = Field(index=True, unique=True)
    displayname: str
    picture: str
    password: str
    isadmin: int

class BroadcastProgram(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    streamer: int | None = Field(default=None, foreign_key="user.id")
    title: str
    url: str
    latitude: int
    longitude: int
    floor: int
    year: int
    month: int
    day: int
    hour: int
    price: int
    btname: str
    broadcastcode: str
    approval: int

class Rights(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    listener: int | None = Field(default=None, foreign_key="user.id")
    program: int | None = Field(default=None, foreign_key="broadcastprogram.id")

# DB関連の処理
sqlite_file_name = "database.db"
sqlite_url = f"sqlite:///{sqlite_file_name}"

connect_args = {"check_same_thread": False}
engine = create_engine(sqlite_url, connect_args=connect_args)

def create_db_and_tables():
    SQLModel.metadata.create_all(engine)

def get_session():
    with Session(engine) as session:
        yield session

SessionDep = Annotated[Session, Depends(get_session)]

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# 認証関連の処理
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


# ここからが本当の処理
app = FastAPI()

# ブラウザがエラーを出すことの対応
origins = [
    "http://localhost",
    "http://192.168.92.129",
    "https://localhost",
    "https://192.168.92.129",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 認証処理
async def get_current_user(session: SessionDep, token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except InvalidTokenError:
        raise credentials_exception
    user = session.exec(select(User).where(User.email == token_data.username)).first()
    if user is None:
        raise credentials_exception
    return user

async def get_current_active_user(
    session: SessionDep, 
    current_user: User = Depends(get_current_user)
):
    return current_user

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def authenticate_user(username: str, password: str, session: SessionDep):
    user = session.exec(select(User).where(User.email == username)).first()
    if user.password != password:
        return None
    return user

# DB作成
@app.on_event("startup")
def on_startup():
    create_db_and_tables()

# ここからREST APIの実装

# テスト用API
# @app.get("/")
# def hello():
#     return {"message":"Hello World!"}

# ログイン処理
@app.post("/token/")
async def login_for_access_token(session: SessionDep, form_data: OAuth2PasswordRequestForm = Depends()) -> Token:
    user = authenticate_user(form_data.username, form_data.password, session)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": form_data.username}, expires_delta=access_token_expires
    )
    return Token(access_token=access_token, token_type="bearer")

# ユーザ登録
@app.post("/users/")
def create_user(
    inputuser: InputUser, 
    session: SessionDep
) -> User:
    user = User()
    user.email = inputuser.email
    user.displayname = inputuser.displayname
    user.picture = inputuser.picture
    user.password = inputuser.password
    user.isadmin = inputuser.isadmin
    
    session.add(user)
    session.commit()
    session.refresh(user)
    return user

# ユーザ一覧取得
@app.get("/users/")
def read_users(
    session: SessionDep,
    offset: int = 0,
    limit: Annotated[int, Query(le=100)] = 100,
    current_user: User = Depends(get_current_active_user)
) -> list[User]:
    users = session.exec(select(User).offset(offset).limit(limit)).all()
    return users

# テスト用API（ログインユーザ取得）
# @app.get("/whoami/")
# def read_user_me(current_user: User = Depends(get_current_active_user)) -> User:
#     return current_user

# 配信プログラム登録
@app.post("/programs/")
def create_program(
    inputbroadcastprogram: InputBroadcastProgram, 
    session: SessionDep,
    current_user: User = Depends(get_current_active_user)
) -> BroadcastProgram:
    broadcastprogram = BroadcastProgram()
    
    broadcastprogram.streamer = current_user.id
    broadcastprogram.title = inputbroadcastprogram.title
    broadcastprogram.url = inputbroadcastprogram.url
    broadcastprogram.latitude = inputbroadcastprogram.latitude
    broadcastprogram.longitude = inputbroadcastprogram.longitude
    broadcastprogram.floor = inputbroadcastprogram.floor
    broadcastprogram.year = inputbroadcastprogram.year
    broadcastprogram.month = inputbroadcastprogram.month
    broadcastprogram.day = inputbroadcastprogram.day
    broadcastprogram.hour = inputbroadcastprogram.hour
    broadcastprogram.price = inputbroadcastprogram.price
    broadcastprogram.btname = inputbroadcastprogram.btname
    broadcastprogram.broadcastcode = inputbroadcastprogram.broadcastcode
    broadcastprogram.approval = 0
    
    session.add(broadcastprogram)
    session.commit()
    session.refresh(broadcastprogram)
    return broadcastprogram

# 配信プログラム登録
@app.post("/bulkprograms/")
def bulk_create_program(
    inputbroadcastprogram: BulkInputBroadcastProgram, 
    session: SessionDep
) -> BroadcastProgram:
    broadcastprogram = BroadcastProgram()
    
    broadcastprogram.streamer = inputbroadcastprogram.streamer
    broadcastprogram.title = inputbroadcastprogram.title
    broadcastprogram.url = inputbroadcastprogram.url
    broadcastprogram.latitude = inputbroadcastprogram.latitude
    broadcastprogram.longitude = inputbroadcastprogram.longitude
    broadcastprogram.floor = inputbroadcastprogram.floor
    broadcastprogram.year = inputbroadcastprogram.year
    broadcastprogram.month = inputbroadcastprogram.month
    broadcastprogram.day = inputbroadcastprogram.day
    broadcastprogram.hour = inputbroadcastprogram.hour
    broadcastprogram.price = inputbroadcastprogram.price
    broadcastprogram.btname = inputbroadcastprogram.btname
    broadcastprogram.broadcastcode = inputbroadcastprogram.broadcastcode
    broadcastprogram.approval = 0
    
    session.add(broadcastprogram)
    session.commit()
    session.refresh(broadcastprogram)
    return broadcastprogram

# プログラム一覧取得
@app.get("/programs/")
def read_programs(
    session: SessionDep,
    offset: int = 0,
    limit: Annotated[int, Query(le=100)] = 100,
    programsearchdata: ProgramSearchData = Depends(ProgramSearchData), 
    current_user: User = Depends(get_current_active_user)
) -> list[OutputBroadcastProgram]:
    if programsearchdata.approval is None:
        if current_user.isadmin == 1:
            statement = select(BroadcastProgram, User).where(BroadcastProgram.streamer == User.id).offset(offset).limit(limit)
        else:
            statement = select(BroadcastProgram, User).where(BroadcastProgram.streamer == User.id).where(BroadcastProgram.streamer == current_user.id).offset(offset).limit(limit)
        
        results = session.exec(statement).all();
        
        outputbroadcastprogramlist = [];
        for broadcastprogram, user in results:
            outputbroadcastprogram = OutputBroadcastProgram();
            
            outputbroadcastprogram.id = broadcastprogram.id;
            outputbroadcastprogram.streamername = user.displayname;
            outputbroadcastprogram.streamerpicture = user.picture;
            outputbroadcastprogram.title = broadcastprogram.title;
            outputbroadcastprogram.url = broadcastprogram.url;
            outputbroadcastprogram.latitude = broadcastprogram.latitude;
            outputbroadcastprogram.longitude = broadcastprogram.longitude;
            outputbroadcastprogram.floor = broadcastprogram.floor;
            outputbroadcastprogram.year = broadcastprogram.year;
            outputbroadcastprogram.month = broadcastprogram.month;
            outputbroadcastprogram.day = broadcastprogram.day;
            outputbroadcastprogram.hour = broadcastprogram.hour;
            outputbroadcastprogram.price = broadcastprogram.price;
            outputbroadcastprogram.btname = broadcastprogram.btname;
            outputbroadcastprogram.rights = 0;
            outputbroadcastprogramlist.append(outputbroadcastprogram);
    elif programsearchdata.approval == 0:
        results = session.exec(
        select(BroadcastProgram, User)
        .where(BroadcastProgram.streamer == User.id)
        .where(BroadcastProgram.approval == 0)
        .offset(offset).limit(limit)).all();
        
        outputbroadcastprogramlist = [];
        for broadcastprogram, user in results:
            outputbroadcastprogram = OutputBroadcastProgram();
            
            outputbroadcastprogram.id = broadcastprogram.id;
            outputbroadcastprogram.streamername = user.displayname;
            outputbroadcastprogram.streamerpicture = user.picture;
            outputbroadcastprogram.title = broadcastprogram.title;
            outputbroadcastprogram.url = broadcastprogram.url;
            outputbroadcastprogram.latitude = broadcastprogram.latitude;
            outputbroadcastprogram.longitude = broadcastprogram.longitude;
            outputbroadcastprogram.floor = broadcastprogram.floor;
            outputbroadcastprogram.year = broadcastprogram.year;
            outputbroadcastprogram.month = broadcastprogram.month;
            outputbroadcastprogram.day = broadcastprogram.day;
            outputbroadcastprogram.hour = broadcastprogram.hour;
            outputbroadcastprogram.price = broadcastprogram.price;
            outputbroadcastprogram.btname = broadcastprogram.btname;
            outputbroadcastprogram.rights = 0;
            outputbroadcastprogramlist.append(outputbroadcastprogram);
    elif programsearchdata.btname is None:
        results = session.exec(
        select(BroadcastProgram, User)
        .where(BroadcastProgram.streamer == User.id)
        .where(BroadcastProgram.approval == 1)
        .where(BroadcastProgram.latitude > programsearchdata.latitude - 10, BroadcastProgram.latitude < programsearchdata.latitude + 10)
        .where(BroadcastProgram.longitude > programsearchdata.longitude - 10, BroadcastProgram.longitude < programsearchdata.longitude + 10)
        .where(BroadcastProgram.year == programsearchdata.year)
        .where(BroadcastProgram.month == programsearchdata.month)
        .where(BroadcastProgram.day == programsearchdata.day)
        .where(BroadcastProgram.hour > programsearchdata.hour - 1, BroadcastProgram.hour < programsearchdata.hour + 1)
        .offset(offset).limit(limit)).all();
        
        rightsdata = session.exec(select(Rights).where(Rights.listener == current_user.id).offset(offset).limit(limit)).all();
        
        outputbroadcastprogramlist = [];
        for broadcastprogram, user in results:
            outputbroadcastprogram = OutputBroadcastProgram();
            
            outputbroadcastprogram.id = broadcastprogram.id;
            outputbroadcastprogram.streamername = user.displayname;
            outputbroadcastprogram.streamerpicture = user.picture;
            outputbroadcastprogram.title = broadcastprogram.title;
            outputbroadcastprogram.url = broadcastprogram.url;
            outputbroadcastprogram.latitude = broadcastprogram.latitude;
            outputbroadcastprogram.longitude = broadcastprogram.longitude;
            outputbroadcastprogram.floor = broadcastprogram.floor;
            outputbroadcastprogram.year = broadcastprogram.year;
            outputbroadcastprogram.month = broadcastprogram.month;
            outputbroadcastprogram.day = broadcastprogram.day;
            outputbroadcastprogram.hour = broadcastprogram.hour;
            outputbroadcastprogram.price = broadcastprogram.price;
            outputbroadcastprogram.btname = broadcastprogram.btname;
            outputbroadcastprogram.rights = 0;
            for rights in rightsdata:
                if rights.program == broadcastprogram.id:
                    outputbroadcastprogram.rights = 1;
            
            outputbroadcastprogramlist.append(outputbroadcastprogram);
    else:
        results = session.exec(
        select(BroadcastProgram, User)
        .where(BroadcastProgram.streamer == User.id)
        .where(BroadcastProgram.approval == 1)
        .where(BroadcastProgram.latitude > programsearchdata.latitude - 10, BroadcastProgram.latitude < programsearchdata.latitude + 10)
        .where(BroadcastProgram.longitude > programsearchdata.longitude - 10, BroadcastProgram.longitude < programsearchdata.longitude + 10)
        .where(BroadcastProgram.floor == programsearchdata.floor)
        .where(BroadcastProgram.year == programsearchdata.year)
        .where(BroadcastProgram.month == programsearchdata.month)
        .where(BroadcastProgram.day == programsearchdata.day)
        .where(BroadcastProgram.hour > programsearchdata.hour - 1, BroadcastProgram.hour < programsearchdata.hour + 1)
        .where(BroadcastProgram.btname == programsearchdata.btname)
        .offset(offset).limit(limit)).all();
        
        rightsdata = session.exec(select(Rights).where(Rights.listener == current_user.id).offset(offset).limit(limit)).all();
        
        outputbroadcastprogramlist = [];
        for broadcastprogram, user in results:
            outputbroadcastprogram = OutputBroadcastProgram();
            
            outputbroadcastprogram.id = broadcastprogram.id;
            outputbroadcastprogram.streamername = user.displayname;
            outputbroadcastprogram.streamerpicture = user.picture;
            outputbroadcastprogram.title = broadcastprogram.title;
            outputbroadcastprogram.url = broadcastprogram.url;
            outputbroadcastprogram.latitude = broadcastprogram.latitude;
            outputbroadcastprogram.longitude = broadcastprogram.longitude;
            outputbroadcastprogram.floor = broadcastprogram.floor;
            outputbroadcastprogram.year = broadcastprogram.year;
            outputbroadcastprogram.month = broadcastprogram.month;
            outputbroadcastprogram.day = broadcastprogram.day;
            outputbroadcastprogram.hour = broadcastprogram.hour;
            outputbroadcastprogram.price = broadcastprogram.price;
            outputbroadcastprogram.btname = broadcastprogram.btname;
            outputbroadcastprogram.rights = 0;
            for rights in rightsdata:
                if rights.program == broadcastprogram.id:
                    outputbroadcastprogram.rights = 1;
            
            outputbroadcastprogramlist.append(outputbroadcastprogram);
    
    return outputbroadcastprogramlist;

# プログラム承認
@app.post("/approve/")
def approve_program(
    approvedata: ApproveData, 
    session: SessionDep,
    current_user: User = Depends(get_current_active_user)
) -> BroadcastProgram:
    program = session.exec(select(BroadcastProgram).where(BroadcastProgram.id == approvedata.id)).first();
    program.approval = 1;
    session.add(program);
    session.commit()
    session.refresh(program)
    
    return program;

# 視聴権購入
@app.post("/buy/")
def buy_program(
    buydata: BuyData, 
    session: SessionDep,
    current_user: User = Depends(get_current_active_user)
) -> BroadcastProgram:
    rights = Rights()
    rights.listener = current_user.id
    rights.program = buydata.id
    
    session.add(rights)
    session.commit()
    session.refresh(rights)
    
    broadcastprogram = session.exec(select(BroadcastProgram).where(BroadcastProgram.id == buydata.id)).first();
    return broadcastprogram


