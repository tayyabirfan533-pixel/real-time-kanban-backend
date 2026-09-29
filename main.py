import os
import json
from datetime import datetime, timedelta
from typing import Optional

from dotenv import load_dotenv
from fastapi import FastAPI, Depends, HTTPException, WebSocket, WebSocketDisconnect, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy import (
    create_engine,
    Column,
    Integer,
    String,
    Text,
    DateTime,
    ForeignKey,
    Float,
)
from sqlalchemy.orm import declarative_base, sessionmaker, Session, relationship

# =========================================================
# CONFIG
# =========================================================

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
SECRET_KEY = os.getenv("SECRET_KEY", "change-this-secret")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

app = FastAPI(title="Real-Time Kanban Board API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =========================================================
# DATABASE MODELS
# =========================================================

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    email = Column(String(150), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)


class Board(Base):
    __tablename__ = "boards"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(150), nullable=False)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)


class BoardMember(Base):
    __tablename__ = "board_members"

    id = Column(Integer, primary_key=True, index=True)
    board_id = Column(Integer, ForeignKey("boards.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    role = Column(String(20), default="viewer")


class KanbanList(Base):
    __tablename__ = "lists"

    id = Column(Integer, primary_key=True, index=True)
    board_id = Column(Integer, ForeignKey("boards.id"), nullable=False)
    name = Column(String(150), nullable=False)
    position = Column(Float, default=0)


class Card(Base):
    __tablename__ = "cards"

    id = Column(Integer, primary_key=True, index=True)
    list_id = Column(Integer, ForeignKey("lists.id"), nullable=False)
    title = Column(String(200), nullable=False)
    description = Column(Text, default="")
    due_date = Column(DateTime, nullable=True)
    position = Column(Float, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)


class ActivityLog(Base):
    __tablename__ = "activity_logs"

    id = Column(Integer, primary_key=True, index=True)
    board_id = Column(Integer, ForeignKey("boards.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    action = Column(String(100), nullable=False)
    details = Column(Text, default="")
    created_at = Column(DateTime, default=datetime.utcnow)


Base.metadata.create_all(bind=engine)


# =========================================================
# SCHEMAS
# =========================================================

class RegisterRequest(BaseModel):
    name: str
    email: str
    password: str


class LoginRequest(BaseModel):
    email: str
    password: str


class BoardCreate(BaseModel):
    name: str


class BoardMemberCreate(BaseModel):
    email: str
    role: str = "viewer"


class ListCreate(BaseModel):
    name: str
    position: float = 0


class ListUpdate(BaseModel):
    name: Optional[str] = None
    position: Optional[float] = None


class CardCreate(BaseModel):
    title: str
    description: str = ""
    due_date: Optional[datetime] = None
    position: float = 0


class CardUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    due_date: Optional[datetime] = None
    position: Optional[float] = None
    list_id: Optional[int] = None


# =========================================================
# DATABASE DEPENDENCY
# =========================================================

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# =========================================================
# AUTH
# =========================================================

def hash_password(password: str):
    return pwd_context.hash(password)


def verify_password(password: str, hashed_password: str):
    return pwd_context.verify(password, hashed_password)


def create_token(user_id: int):
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    payload = {
        "sub": str(user_id),
        "exp": expire,
    }

    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token",
    )

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")

        if not user_id:
            raise credentials_exception

    except JWTError:
        raise credentials_exception

    user = db.query(User).filter(User.id == int(user_id)).first()

    if not user:
        raise credentials_exception

    return user


# =========================================================
# BOARD ACCESS / ROLES
# =========================================================

def get_board_role(db: Session, board_id: int, user_id: int):
    board = db.query(Board).filter(Board.id == board_id).first()

    if not board:
        raise HTTPException(status_code=404, detail="Board not found")

    if board.owner_id == user_id:
        return "owner"

    member = (
        db.query(BoardMember)
        .filter(
            BoardMember.board_id == board_id,
            BoardMember.user_id == user_id,
        )
        .first()
    )

    if not member:
        raise HTTPException(
            status_code=403,
            detail="You are not a member of this board",
        )

    return member.role


def require_editor(db: Session, board_id: int, user_id: int):
    role = get_board_role(db, board_id, user_id)

    if role not in ["owner", "editor"]:
        raise HTTPException(
            status_code=403,
            detail="Viewer cannot modify this board",
        )

    return role


# =========================================================
# ACTIVITY LOG
# =========================================================

def create_activity(
    db: Session,
    board_id: int,
    user_id: int,
    action: str,
    details: str = "",
):
    activity = ActivityLog(
        board_id=board_id,
        user_id=user_id,
        action=action,
        details=details,
    )

    db.add(activity)


# =========================================================
# WEBSOCKET MANAGER
# =========================================================

class ConnectionManager:
    def __init__(self):
        self.connections = {}

    async def connect(self, board_id: int, websocket: WebSocket):
        await websocket.accept()

        if board_id not in self.connections:
            self.connections[board_id] = []

        self.connections[board_id].append(websocket)

    def disconnect(self, board_id: int, websocket: WebSocket):
        if board_id in self.connections:
            if websocket in self.connections[board_id]:
                self.connections[board_id].remove(websocket)

            if not self.connections[board_id]:
                del self.connections[board_id]

    async def broadcast(self, board_id: int, message: dict):
        if board_id not in self.connections:
            return

        disconnected = []

        for websocket in self.connections[board_id]:
            try:
                await websocket.send_json(message)
            except Exception:
                disconnected.append(websocket)

        for websocket in disconnected:
            self.disconnect(board_id, websocket)


manager = ConnectionManager()


async def board_changed(board_id: int, action: str, data=None):
    await manager.broadcast(
        board_id,
        {
            "type": "board_update",
            "action": action,
            "data": data,
        },
    )


# =========================================================
# BASIC ROUTES
# =========================================================

@app.get("/")
def root():
    return {
        "message": "Real-Time Kanban Board API",
        "status": "running",
    }


@app.get("/health")
def health():
    return {"status": "healthy"}


# =========================================================
# AUTH ROUTES
# =========================================================

@app.post("/api/auth/register")
def register(data: RegisterRequest, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.email == data.email).first()

    if existing:
        raise HTTPException(
            status_code=400,
            detail="Email already registered",
        )

    user = User(
        name=data.name,
        email=data.email,
        password_hash=hash_password(data.password),
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    token = create_token(user.id)

    return {
        "message": "Registration successful",
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": user.id,
            "name": user.name,
            "email": user.email,
        },
    }


@app.post("/api/auth/login")
def login(data: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == data.email).first()

    if not user or not verify_password(data.password, user.password_hash):
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password",
        )

    token = create_token(user.id)

    return {
        "message": "Login successful",
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": user.id,
            "name": user.name,
            "email": user.email,
        },
    }


@app.get("/api/auth/me")
def me(current_user: User = Depends(get_current_user)):
    return {
        "id": current_user.id,
        "name": current_user.name,
        "email": current_user.email,
    }


# =========================================================
# BOARD ROUTES
# =========================================================

@app.post("/api/boards")
async def create_board(
    data: BoardCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    board = Board(
        name=data.name,
        owner_id=current_user.id,
    )

    db.add(board)
    db.commit()
    db.refresh(board)

    create_activity(
        db,
        board.id,
        current_user.id,
        "created_board",
        f"Created board '{board.name}'",
    )

    db.commit()

    return {
        "id": board.id,
        "name": board.name,
        "owner_id": board.owner_id,
    }


@app.get("/api/boards")
def get_boards(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    owned = db.query(Board).filter(Board.owner_id == current_user.id).all()

    member_board_ids = (
        db.query(BoardMember.board_id)
        .filter(BoardMember.user_id == current_user.id)
        .all()
    )

    member_ids = [x[0] for x in member_board_ids]

    member_boards = []

    if member_ids:
        member_boards = (
            db.query(Board)
            .filter(Board.id.in_(member_ids))
            .all()
        )

    boards = {board.id: board for board in owned + member_boards}

    return [
        {
            "id": board.id,
            "name": board.name,
            "owner_id": board.owner_id,
        }
        for board in boards.values()
    ]


@app.get("/api/boards/{board_id}")
def get_board(
    board_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    get_board_role(db, board_id, current_user.id)

    board = db.query(Board).filter(Board.id == board_id).first()

    lists = (
        db.query(KanbanList)
        .filter(KanbanList.board_id == board_id)
        .order_by(KanbanList.position)
        .all()
    )

    result_lists = []

    for kanban_list in lists:
        cards = (
            db.query(Card)
            .filter(Card.list_id == kanban_list.id)
            .order_by(Card.position)
            .all()
        )

        result_lists.append(
            {
                "id": kanban_list.id,
                "name": kanban_list.name,
                "position": kanban_list.position,
                "cards": [
                    {
                        "id": card.id,
                        "title": card.title,
                        "description": card.description,
                        "due_date": card.due_date,
                        "position": card.position,
                        "list_id": card.list_id,
                    }
                    for card in cards
                ],
            }
        )

    return {
        "id": board.id,
        "name": board.name,
        "owner_id": board.owner_id,
        "lists": result_lists,
    }


@app.delete("/api/boards/{board_id}")
async def delete_board(
    board_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    board = db.query(Board).filter(Board.id == board_id).first()

    if not board:
        raise HTTPException(status_code=404, detail="Board not found")

    if board.owner_id != current_user.id:
        raise HTTPException(
            status_code=403,
            detail="Only owner can delete board",
        )

    lists = db.query(KanbanList).filter(
        KanbanList.board_id == board_id
    ).all()

    for kanban_list in lists:
        db.query(Card).filter(
            Card.list_id == kanban_list.id
        ).delete()

    db.query(KanbanList).filter(
        KanbanList.board_id == board_id
    ).delete()

    db.query(BoardMember).filter(
        BoardMember.board_id == board_id
    ).delete()

    db.query(ActivityLog).filter(
        ActivityLog.board_id == board_id
    ).delete()

    db.delete(board)
    db.commit()

    await board_changed(board_id, "board_deleted")

    return {"message": "Board deleted"}


# =========================================================
# BOARD SHARING
# =========================================================

@app.post("/api/boards/{board_id}/members")
async def add_member(
    board_id: int,
    data: BoardMemberCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    board = db.query(Board).filter(Board.id == board_id).first()

    if not board:
        raise HTTPException(status_code=404, detail="Board not found")

    if board.owner_id != current_user.id:
        raise HTTPException(
            status_code=403,
            detail="Only owner can invite members",
        )

    if data.role not in ["editor", "viewer"]:
        raise HTTPException(
            status_code=400,
            detail="Role must be editor or viewer",
        )

    user = db.query(User).filter(User.email == data.email).first()

    if not user:
        raise HTTPException(
            status_code=404,
            detail="User with this email does not exist",
        )

    if user.id == current_user.id:
        raise HTTPException(
            status_code=400,
            detail="Owner is already a member",
        )

    existing = (
        db.query(BoardMember)
        .filter(
            BoardMember.board_id == board_id,
            BoardMember.user_id == user.id,
        )
        .first()
    )

    if existing:
        existing.role = data.role
    else:
        existing = BoardMember(
            board_id=board_id,
            user_id=user.id,
            role=data.role,
        )
        db.add(existing)

    create_activity(
        db,
        board_id,
        current_user.id,
        "member_added",
        f"Added {user.email} as {data.role}",
    )

    db.commit()

    await board_changed(
        board_id,
        "member_updated",
        {
            "email": user.email,
            "role": data.role,
        },
    )

    return {
        "message": "Member added",
        "email": user.email,
        "role": data.role,
    }


@app.get("/api/boards/{board_id}/members")
def get_members(
    board_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    get_board_role(db, board_id, current_user.id)

    members = (
        db.query(BoardMember, User)
        .join(User, BoardMember.user_id == User.id)
        .filter(BoardMember.board_id == board_id)
        .all()
    )

    return [
        {
            "user_id": user.id,
            "name": user.name,
            "email": user.email,
            "role": member.role,
        }
        for member, user in members
    ]


# =========================================================
# LIST ROUTES
# =========================================================

@app.post("/api/boards/{board_id}/lists")
async def create_list(
    board_id: int,
    data: ListCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    require_editor(db, board_id, current_user.id)

    kanban_list = KanbanList(
        board_id=board_id,
        name=data.name,
        position=data.position,
    )

    db.add(kanban_list)
    db.flush()

    create_activity(
        db,
        board_id,
        current_user.id,
        "created_list",
        f"Created list '{kanban_list.name}'",
    )

    db.commit()
    db.refresh(kanban_list)

    await board_changed(
        board_id,
        "list_created",
        {
            "id": kanban_list.id,
            "name": kanban_list.name,
            "position": kanban_list.position,
        },
    )

    return {
        "id": kanban_list.id,
        "name": kanban_list.name,
        "position": kanban_list.position,
    }


@app.patch("/api/lists/{list_id}")
async def update_list(
    list_id: int,
    data: ListUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    kanban_list = db.query(KanbanList).filter(
        KanbanList.id == list_id
    ).first()

    if not kanban_list:
        raise HTTPException(status_code=404, detail="List not found")

    require_editor(db, kanban_list.board_id, current_user.id)

    if data.name is not None:
        kanban_list.name = data.name

    if data.position is not None:
        kanban_list.position = data.position

    create_activity(
        db,
        kanban_list.board_id,
        current_user.id,
        "updated_list",
        f"Updated list {kanban_list.id}",
    )

    db.commit()

    await board_changed(
        kanban_list.board_id,
        "list_updated",
        {
            "id": kanban_list.id,
            "name": kanban_list.name,
            "position": kanban_list.position,
        },
    )

    return {"message": "List updated"}


@app.delete("/api/lists/{list_id}")
async def delete_list(
    list_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    kanban_list = db.query(KanbanList).filter(
        KanbanList.id == list_id
    ).first()

    if not kanban_list:
        raise HTTPException(status_code=404, detail="List not found")

    board_id = kanban_list.board_id

    require_editor(db, board_id, current_user.id)

    db.query(Card).filter(Card.list_id == list_id).delete()

    create_activity(
        db,
        board_id,
        current_user.id,
        "deleted_list",
        f"Deleted list {list_id}",
    )

    db.delete(kanban_list)
    db.commit()

    await board_changed(
        board_id,
        "list_deleted",
        {"list_id": list_id},
    )

    return {"message": "List deleted"}


# =========================================================
# CARD ROUTES
# =========================================================

def card_board_id(db: Session, card: Card):
    kanban_list = db.query(KanbanList).filter(
        KanbanList.id == card.list_id
    ).first()

    if not kanban_list:
        raise HTTPException(status_code=404, detail="List not found")

    return kanban_list.board_id


@app.post("/api/lists/{list_id}/cards")
async def create_card(
    list_id: int,
    data: CardCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    kanban_list = db.query(KanbanList).filter(
        KanbanList.id == list_id
    ).first()

    if not kanban_list:
        raise HTTPException(status_code=404, detail="List not found")

    board_id = kanban_list.board_id

    require_editor(db, board_id, current_user.id)

    card = Card(
        list_id=list_id,
        title=data.title,
        description=data.description,
        due_date=data.due_date,
        position=data.position,
    )

    db.add(card)
    db.flush()

    create_activity(
        db,
        board_id,
        current_user.id,
        "created_card",
        f"Created card '{card.title}'",
    )

    db.commit()
    db.refresh(card)

    payload = {
        "id": card.id,
        "title": card.title,
        "description": card.description,
        "due_date": card.due_date,
        "position": card.position,
        "list_id": card.list_id,
    }

    await board_changed(board_id, "card_created", payload)

    return payload


@app.patch("/api/cards/{card_id}")
async def update_card(
    card_id: int,
    data: CardUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    card = db.query(Card).filter(Card.id == card_id).first()

    if not card:
        raise HTTPException(status_code=404, detail="Card not found")

    board_id = card_board_id(db, card)

    require_editor(db, board_id, current_user.id)

    if data.title is not None:
        card.title = data.title

    if data.description is not None:
        card.description = data.description

    if data.due_date is not None:
        card.due_date = data.due_date

    if data.position is not None:
        card.position = data.position

    if data.list_id is not None:
        new_list = db.query(KanbanList).filter(
            KanbanList.id == data.list_id
        ).first()

        if not new_list:
            raise HTTPException(
                status_code=404,
                detail="New list not found",
            )

        if new_list.board_id != board_id:
            raise HTTPException(
                status_code=400,
                detail="Card cannot move to another board",
            )

        card.list_id = data.list_id

    create_activity(
        db,
        board_id,
        current_user.id,
        "updated_card",
        f"Updated card {card.id}",
    )

    db.commit()
    db.refresh(card)

    payload = {
        "id": card.id,
        "title": card.title,
        "description": card.description,
        "due_date": card.due_date,
        "position": card.position,
        "list_id": card.list_id,
    }

    await board_changed(board_id, "card_updated", payload)

    return payload


@app.delete("/api/cards/{card_id}")
async def delete_card(
    card_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    card = db.query(Card).filter(Card.id == card_id).first()

    if not card:
        raise HTTPException(status_code=404, detail="Card not found")

    board_id = card_board_id(db, card)

    require_editor(db, board_id, current_user.id)

    db.delete(card)

    create_activity(
        db,
        board_id,
        current_user.id,
        "deleted_card",
        f"Deleted card {card_id}",
    )

    db.commit()

    await board_changed(
        board_id,
        "card_deleted",
        {"card_id": card_id},
    )

    return {"message": "Card deleted"}


# =========================================================
# ACTIVITY LOG
# =========================================================

@app.get("/api/boards/{board_id}/activity")
def get_activity(
    board_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    get_board_role(db, board_id, current_user.id)

    activities = (
        db.query(ActivityLog, User)
        .join(User, ActivityLog.user_id == User.id)
        .filter(ActivityLog.board_id == board_id)
        .order_by(ActivityLog.created_at.desc())
        .limit(100)
        .all()
    )

    return [
        {
            "id": activity.id,
            "user_id": user.id,
            "user_name": user.name,
            "action": activity.action,
            "details": activity.details,
            "created_at": activity.created_at,
        }
        for activity, user in activities
    ]


# =========================================================
# WEBSOCKET
# =========================================================

@app.websocket("/ws/boards/{board_id}")
async def websocket_endpoint(
    websocket: WebSocket,
    board_id: int,
):
    db = SessionLocal()

    try:
        await manager.connect(board_id, websocket)

        await websocket.send_json(
            {
                "type": "connected",
                "board_id": board_id,
                "message": "Connected to real-time board",
            }
        )

        while True:
            data = await websocket.receive_text()

            try:
                message = json.loads(data)
            except json.JSONDecodeError:
                message = {"type": "message", "data": data}

            await manager.broadcast(
                board_id,
                {
                    "type": "realtime_message",
                    "board_id": board_id,
                    "data": message,
                },
            )

    except WebSocketDisconnect:
        manager.disconnect(board_id, websocket)

    except Exception:
        manager.disconnect(board_id, websocket)

    finally:
        db.close()


# =========================================================
# STARTUP
# =========================================================

@app.on_event("startup")
def startup():
    print("======================================")
    print("Real-Time Kanban Board API Started")
    print("Database connected")
    print("======================================")