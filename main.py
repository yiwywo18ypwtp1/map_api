import json
from datetime import datetime, timedelta

import fastapi
from fastapi import FastAPI, Depends, HTTPException, status, Response
from jose import jwt, JWTError
from pydantic import Field, BaseModel, EmailStr
from sqlalchemy.exc import IntegrityError, DatabaseError
from sqlalchemy.orm import Session, Query
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

@app.get("/check-redis")
async def check_redis():
    try:
        pong = await app.state.redis.ping()
        if pong:
            return {"message": "Redis is up and running!"}
    except Exception as e:
        return {"error": str(e)}





@app.post("/request-password-reset")
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

@app.post("/reset-password")
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
    db: Session = Depends(get_db),
):
    existing_user = db.query(User).filter(User.username == username).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="user already exists",
        )

    hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    new_user = User(username=username, password=hashed_password, email=email)
    db.add(new_user)
    db.commit()

    return {"message": "user registred succses", "username": username, "email": email}

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
            detail="invalid username or password",
        )

    session_token = create_session(user.id)

    await app.state.redis.set(f"session:{session_token}", user.id, ex=86400)

    # кукііі
    response.set_cookie(key="session_token", value=session_token, httponly=True)
    return {"message": "login success"}


@app.post("/logout")
async def logout(response: Response):
    # Видалення cookies
    response.delete_cookie(key="session_token")
    return {"message": "logout success"}





# @app.get("/all-locations")
# async def all_locations(db: Session = Depends(get_db)):
#     locations = db.query(
#         Location.id,
#         Location.name,
#         case(
#             (Location.comments > 0, Location.rating / Location.comments),
#             else_=0
#         ).label("rating"),
#         Location.likes,
#         Location.dislikes,
#     ).all()
#
#     result = [
#         {
#             "id": loc.id,
#             "name": loc.name,
#             "rating": loc.rating,
#             "likes": loc.likes,
#             "dislikes": loc.dislikes,
#         }
#         for loc in locations
#     ]
#
#     return {"locations": result}

@app.get("/all-locations")
async def all_locations(db: Session = Depends(get_db)):
    redis_key = "all_locations"
    cached_locations = await app.state.redis.get(redis_key)

    if cached_locations:
        return {"locations": json.loads(cached_locations)}

    locations = db.query(
        Location.id,
        Location.name,
        case(
            (Location.comments > 0, Location.rating / Location.comments),
            else_=0
        ).label("rating"),
        Location.likes,
        Location.dislikes,
    ).all()

    result = [
        {
            "id": loc.id,
            "name": loc.name,
            "rating": loc.rating,
            "likes": loc.likes,
            "dislikes": loc.dislikes,
        }
        for loc in locations
    ]

    await app.state.redis.set(redis_key, json.dumps(result), ex=3600)

    return {"locations": result}


@app.post("/add-location")
async def add_location(
    name: str,
    about: str,
    db: Session = Depends(get_db),
):
    try:
        new_location = Location(
            name=name,
            about=about,
        )
        db.add(new_location)
        db.commit()
        return {"loc added": str(new_location)}
    except IntegrityError as ex:
        db.rollback()
        return {"error": "location already exists"}

@app.post("/add-review")
def add_review(
        searched_location: str,
        author: str,
        text: str,
        like: bool, dislike: bool,
        rating: float = fastapi.Query(gt=0, lt=10),

        db: Session = Depends(get_db)
):
    location = db.query(Location).filter(Location.name == searched_location).first()

    if not location:
        raise HTTPException(status_code=404, detail="Location not found")

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

@app.post("/add-category")
def add_category(
        searched_location: str,
        category_name: str,

        db: Session = Depends(get_db)
):
    location = db.query(Location).filter(Location.name == searched_location).first()

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


@app.get("/read-all-comments")
def read_all_comments(
        searched_location: str,
        db: Session = Depends(get_db)
):
    location = db.query(Location).filter(Location.name == searched_location).first()
    all_comments = db.query(Comment).filter(Comment.loc_id == location.id).all()

    return {"all comments": all_comments}


@app.get("/search-location")
async def search_location(
        search_query: str,
        db: Session = Depends(get_db)
):
    redis_key = f"search_location:{search_query}"

    cached_result = await app.state.redis.get(redis_key)
    if cached_result:
        return {"found location": json.loads(cached_result)}

    found_location = db.query(Location).filter(
        (Location.name.ilike(f"%{search_query}%")) |
        (Location.about.ilike(f"%{search_query}%"))
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



@app.put("edit-location-about")
def edit_location_about(
        searched_location: str,
        new_about: str,

        db: Session = Depends(get_db)
):
    location = db.query(Location).filter(Location.name == searched_location).first()
    location.about = new_about

    return {"location edited": location}


@app.delete("/delete-location")
def search_location(
        location_to_delete: str,

        db : Session = Depends(get_db)
):
    all_locations = db.query(Location).all()

    if location_to_delete in all_locations:
        db.query(Location).filter(Location.name == location_to_delete).delete()
        db.commit()
        return {"message": f"user '{location_to_delete}' has deleted from db"}
    else:
        return {"error": f"there is no object named '{location_to_delete}' in db"}


@app.get("/filter-by-rating")
def filter_by_rating(
        db: Session = Depends(get_db)
):
    sorted_locations = db.query(Location).order_by(Location.rating.desc()).all()
    return {"sorted locations": [loc.name for loc in sorted_locations]}


@app.get("/filter-by-category")
def filter_by_category(
        category: str,

        db: Session = Depends(get_db)
):
    searched_category = db.query(Category).filter(Category.name == category).first()
    sorted_locations = db.query(Location).filter(Location.id == searched_category.loc_id).all()

    return {"sorted locations": [loc.name for loc in sorted_locations]}


@app.get("/dump-to-json")
def export():
    export.export_to_json()

    return {"message": "locations data imported successfully"}


