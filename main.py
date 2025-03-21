from fastapi import FastAPI, Depends, HTTPException, status, Response
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from models import User, Location, get_db, Comment
from itsdangerous import URLSafeSerializer
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import bcrypt

app = FastAPI()

SECRET_KEY = "your-secret-key"
serializer = URLSafeSerializer(SECRET_KEY)

def create_session(user_id: int) -> str:
    return serializer.dumps({"user_id": user_id})

# Функція для отримання даних з сесії
def get_session(session_token: str) -> dict:
    try:
        return serializer.loads(session_token)
    except:
        return None



@app.post("/signup")
async def signup(
    username: str,
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

    new_user = User(username=username, password=hashed_password)
    db.add(new_user)
    db.commit()

    return {"message": "Користувач успішно зареєстрований", "username": username}

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

    # кукііі
    response.set_cookie(key="session_token", value=session_token, httponly=True)
    return {"message": "login success"}

@app.post("/logout")
async def logout(response: Response):
    # Видалення cookies
    response.delete_cookie(key="session_token")
    return {"message": "logout success"}


@app.get("/all_locations")
async def all_locations(db: Session = Depends(get_db)):
    all_locations = db.query(Location).all()
    return {"locations": all_locations}


@app.post("/add_location")
async def add_location(
    name: str,
    about: str,
    db: Session = Depends(get_db),
):
    try:
        loc_to_add = Location(
            name=name,
            about=about,
        )
        db.add(loc_to_add)
        db.commit()
        return {"loc added": str(loc_to_add)}
    except IntegrityError as ex:
        db.rollback()
        return {"error": "location already exists"}

@app.post("/write_com")
def write_com(
        searched_location: str,
        author: str,
        text: str,
        like: bool, dislike: bool,

        db: Session = Depends(get_db)
):
    location = db.query(Location).filter(Location.name == searched_location).first()

    try:
        new_comment = Comment(
            loc_id = location.id,
            author = author,
            text = text,
        )

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


@app.get("/read_all_comments")
def read_all_comments(
        searched_location: str,
        db: Session = Depends(get_db)
):
    location = db.query(Location).filter(Location.name == searched_location).first()
    all_comments = db.query(Comment).filter(Comment.loc_id == location.id).all()

    return {"all comments": all_comments}


@app.get("/search_location")
def search_location(
        searched_field: str,

        db : Session = Depends(get_db)
):
    found_location = db.query(Location).filter(
        (Location.name.ilike(f"%{searched_field}%")) |
        (Location.about.ilike(f"%{searched_field}%"))
    ).first()

    return {"found location": found_location}


@app.put("edit_location_about")
def edit_location_about(
        searched_location: str,
        new_about: str,

        db: Session = Depends(get_db)
):
    location = db.query(Location).filter(Location.name == searched_location).first()
    location.about = new_about

    return {"location": location}


@app.delete("/delete_location")
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


@app.get("/filter_by_like")
def filter_by_like(
        db: Session = Depends(get_db)
):
    sorted_locations = db.query(Location).order_by(Location.likes.desc()).all()
    return {"sorted locations": sorted_locations}







