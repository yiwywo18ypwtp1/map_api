import json
from datetime import datetime, timedelta

import fastapi
from fastapi import FastAPI, Depends, HTTPException, status, Response, Request
from jose import jwt, JWTError
from pydantic import Field, BaseModel, EmailStr
from sqlalchemy.exc import IntegrityError, DatabaseError, NoResultFound
from sqlalchemy.orm import Session, Query
from sqlalchemy.types import Boolean

from models import User, Location, get_db, Comment, Category
from itsdangerous import URLSafeSerializer
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import bcrypt
from sqlalchemy import case
from utils import create_reset_token, send_reset_email
from config import settings
import aioredis

import export

app = FastAPI()

SECRET_KEY = "your-secret-key"
serializer = URLSafeSerializer(SECRET_KEY)


def create_session(user_id: int) -> str:
    return serializer.dumps({"user_id": user_id})


def get_session(session_token: str) -> dict:
    try:
        return serializer.loads(session_token)
    except DatabaseError:
        return {}


class ResetPasswordRequest(BaseModel):
    email: EmailStr

# Модель для нового пароля
class NewPasswordRequest(BaseModel):
    token: str
    new_password: str

async def get_user_id_from_session(request: Request) -> int:
    session_token = request.cookies.get("session_token")
    if not session_token:
        raise HTTPException(status_code=401, detail="User not authenticated")

    user_id = await app.state.redis.get(f"session:{session_token}")

    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid session token")

    return int(user_id)

def get_current_user(db: Session = Depends(get_db), user_id: int = Depends(get_user_id_from_session)) -> User:
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


@app.on_event("startup")
async def startup():
    app.state.redis = await aioredis.from_url(
        "redis://localhost:6379",
        encoding="utf-8",
        decode_responses=True
    )

@app.on_event("shutdown")
async def shutdown():
    await app.state.redis.close()


@app.get("/hello")
def hello(current_user: User = Depends(get_current_user)):
    return {"message": f"Hello, {current_user.username}!"}

@app.get("/redis-status")
async def check_redis():
    try:
        pong = await app.state.redis.ping()
        if pong:
            return {"message": "Redis is up and running!"}
    except Exception as e:
        return {"error": str(e)}



@app.post("/password-reset/request")
async def request_password_reset(
    request: ResetPasswordRequest,
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.email == request.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="user not found")

    reset_token = create_reset_token(user.username)
    user.reset_token = reset_token
    user.reset_token_expiry = datetime.utcnow() + timedelta(minutes=settings.RESET_TOKEN_EXPIRE_MINUTES)
    db.commit()

    await send_reset_email(request.email, reset_token)
    return {"message": "email to reset was sent"}

@app.post("/password-reset")
async def reset_password(
    request: NewPasswordRequest,
    db: Session = Depends(get_db)
):
    try:
        payload = jwt.decode(request.token, settings.SECRET_KEY, algorithms=["HS256"])
        username = payload.get("sub")
        if not username:
            raise HTTPException(status_code=400, detail="invalid token")

        user = db.query(User).filter(User.username == username).first()
        if not user or user.reset_token != request.token or user.reset_token_expiry < datetime.utcnow():
            raise HTTPException(status_code=400, detail="invalid or expired token")

        user.password = bcrypt.hashpw(request.new_password.encode(), bcrypt.gensalt()).decode()
        user.reset_token = None
        user.reset_token_expiry = None
        db.commit()

        return {"message": "password was reset successfully!!!"}
    except JWTError:
        raise HTTPException(status_code=400, detail="invalid token")



@app.post("/signup")
async def signup(
    username: str,
    email: str,
    password: str,
    role: str,
    db: Session = Depends(get_db),
):
    existing_user = db.query(User).filter(User.username == username).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User already exists",
        )

    hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    new_user = User(username=username, password=hashed_password, email=email, role=role)
    db.add(new_user)
    db.commit()

    return {"message": "User registered successfully", "username": username, "email": email, "role": role}


@app.post("/login")
async def login(
        credentials: HTTPBasicCredentials = Depends(HTTPBasic()),
        db: Session = Depends(get_db),
        response: Response = None,
):
    user = db.query(User).filter(User.username == credentials.username).first()
    if not user or not bcrypt.checkpw(credentials.password.encode(), user.password.encode()):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    session_token = create_session(user.id)

    await app.state.redis.set(f"session:{session_token}", user.id, ex=86400)

    # кукі
    response.set_cookie(key="session_token", value=session_token, httponly=True)

    return {"message": "Login success", "username": user.username, "role": user.role}


@app.post("/logout")
async def logout(response: Response):
    response.delete_cookie(key="session_token")
    return {"message": "Logout success"}



@app.get("/locations/read-all")
async def all_locations(
        db: Session = Depends(get_db)
):
    try:
        locations = db.query(
            Location.id,
            Location.name,
            case(
                (Location.comments > 0, Location.rating / Location.comments),
                else_=0
            ).label("rating"),
            Location.likes,
            Location.dislikes,
            Location.owner_id,
            Location.is_aproved
        ).filter(Location.is_aproved==True).all()

        result = [
            {
                "id": loc.id,
                "name": loc.name,
                "rating": loc.rating,
                "likes": loc.likes,
                "dislikes": loc.dislikes,
                "owner": loc.owner_id,
                "is_aproved": loc.is_aproved,
            }
            for loc in locations
        ]
        return {"approved locations:": result}

    except NoResultFound:
        return {"message": "there are no locations in the db"}




@app.post("/locations/new")
async def add_location(
    name: str,
    about: str,

    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    is_approved = True if user.role == "admin" else False
    try:
        new_location = Location(
            name=name,
            about=about,
            owner_id=user.id,
            is_aproved=is_approved
        )

        db.add(new_location)
        db.commit()
        if is_approved:
            return {"message": f"location {new_location.name} has been added"}
        else:
            return {"message": f"location {new_location.name} has been sent for moderation"}
    except IntegrityError as ex:
        db.rollback()
        return {"error": "location already exists"}


@app.post("/locations/reviews/{location_name}")
def add_review(
        location_name: str,
        author: str,
        text: str,
        like: bool, dislike: bool,
        rating: float = fastapi.Query(gt=0, lt=10),

        db: Session = Depends(get_db)
):
    location = db.query(Location).filter(Location.name == location_name).first()

    if not location:
        raise HTTPException(status_code=404, detail="location not found")

    try:
        new_comment = Comment(
            loc_id = location.id,
            author = author,
            text = text,
        )

        location.rating += rating
        location.comments += 1

        if like:
            location.likes+=1

        if dislike:
            location.dislikes+=1

        db.add(new_comment)
        db.commit()

        return {"comment": str(new_comment)}
    except IntegrityError as ex:
        db.rollback()

        return {"error": "this location does not exist"}

@app.post("/locations/categories}/{location_name}")
def add_category(
        location_name: str,
        category_name: str,

        db: Session = Depends(get_db)
):
    location = db.query(Location).filter(Location.name == location_name).first()

    try:
        new_category = Category(
            loc_id = location.id,
            name = category_name,
        )

        db.add(new_category)
        db.commit()

        return {"category created": new_category}
    except IntegrityError as ex:
        db.rollback()

        return {"error": "this location does not exist"}


@app.get("/locations/reviews/read-all/{location_name}")
def read_all_comments(
        location_name: str,
        db: Session = Depends(get_db)
):
    location = db.query(Location).filter(Location.name == location_name).first()
    all_comments = db.query(Comment).filter(Comment.loc_id == location.id).all()

    return {"all comments": all_comments}


@app.get("/locations/search/{query}")
async def search_location(
        query: str,
        db: Session = Depends(get_db)
):
    redis_key = f"search_location:{query}"

    cached_result = await app.state.redis.get(redis_key)
    if cached_result:
        return {"found location": json.loads(cached_result)}

    found_location = db.query(Location).filter(
        (Location.name.ilike(f"%{query}%")) |
        (Location.about.ilike(f"%{query}%"))
    ).first()

    if found_location:
        location_dict = {
            "id": found_location.id,
            "name": found_location.name,
            "about": found_location.about,
            "rating": found_location.rating,
            "likes": found_location.likes,
            "dislikes": found_location.dislikes
        }

        await app.state.redis.set(redis_key, json.dumps(location_dict), ex=600)

        return {"found location": location_dict}


    return {"message": "Location not found"}



@app.put("/locations/edit-about/{location_name}")
def edit_location_about(
        location_name: str,
        new_about: str,

        user = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    location = db.query(Location).filter(Location.name == location_name).first()

    if user.role != "admin":
        if location.owner_id == user.id:
            location.about = new_about
            return {"location edited": location}
        else:
            return {"message": "u have no permissions to edit this location. it isn't yours"}
    else:
        location.about = new_about
        return {"location edited": location}


@app.delete("/locations/delete/{location_name}")
def search_location(
        location_name: str,

        user: User = Depends(get_current_user),
        db : Session = Depends(get_db)
):
    location = db.query(Location).filter(Location.name == location_name).first()

    try:
        if user.role != "admin":
            if location.owner_id == user.id:
                db.query(Location).filter(Location.name == location_name).delete()
                db.commit()
                return {"message": f"location '{location_name}' has deleted from db"}
            else:
                return {"message": "u have no permissions to delete this location"}
        else:
            db.query(Location).filter(Location.name == location_name).delete()
            db.commit()
            return {"message": f"location '{location_name}' has deleted from db"}
    except IntegrityError as ex:
        return {"error": f"there is no object named '{location_name}' in db"}


@app.get("/locations/filter-by-rating")
def filter_by_rating(
        db: Session = Depends(get_db)
):
    sorted_locations = db.query(Location).order_by(Location.rating.desc()).all()
    return {"sorted locations": [loc.name for loc in sorted_locations]}


@app.get("/locations/filter-by-category")
def filter_by_category(
        category: str,

        db: Session = Depends(get_db)
):
    searched_category = db.query(Category).filter(Category.name == category).first()
    sorted_locations = db.query(Location).filter(Location.id == searched_category.loc_id).all()

    return {"sorted locations": [loc.name for loc in sorted_locations]}


@app.get("/locations/dump-to-json")
def export():
    export.export_to_json()

    return {"message": "locations data imported successfully"}



@app.get("/locations/locations-to-aprove")
async def locations_to_aprove(db: Session = Depends(get_db)):
    try:
        locations = db.query(
            Location.id,
            Location.name,
            case(
                (Location.comments > 0, Location.rating / Location.comments),
                else_=0
            ).label("rating"),
            Location.likes,
            Location.dislikes,
            Location.is_aproved
        ).filter(Location.is_aproved==False).all()

        result = [
            {
                "id": loc.id,
                "name": loc.name,
                "rating": loc.rating,
                "likes": loc.likes,
                "dislikes": loc.dislikes,
                "is_aproved": loc.is_aproved,
            }
            for loc in locations
        ]
        return {"unapproved locations:": result}

    except NoResultFound:
        return {"message": "there are no locations in the db"}


@app.post("/approve_location/{location_name}")
def approve_location(
        location_name: str,
        user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    if user.role != "moderator":
        raise HTTPException(status_code=403, detail="u dont have permission to this action")


    location = db.query(Location).filter(Location.name == location_name).first()

    if not location:
        raise HTTPException(status_code=404, detail="location not found")

    location.is_aproved = True
    db.commit()

    return {"message": f"location {location.name} has been approved!"}
