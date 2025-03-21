from sqlalchemy import create_engine, Column, String, Integer, Boolean, ForeignKey
from sqlalchemy.orm import declarative_base, sessionmaker

SQLALCHEMY_DATABASE_URL = "sqlite:///./sql_app.db"
engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}, echo=False
)

Base = declarative_base()

class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, nullable=False)
    password = Column(String, nullable=False)  # Хешований пароль

class Location(Base):
    __tablename__ = 'locations'
    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False, unique=True)
    about = Column(String(255), nullable=False)
    likes = Column(Integer, default=0)
    dislikes = Column(Integer, default=0)

    def __str__(self):
        return f'{self.name}: "{self.about}"'

class Comment(Base):
    __tablename__ = 'comments'
    id = Column(Integer, primary_key=True)
    loc_id = Column(Integer, ForeignKey("locations.id"))
    author = Column(String(255), nullable=False)
    text = Column(String(255), nullable=False)

    def __str__(self):
        return f'{self.author}: "{self.text}"'

class Category(Base):
    __tablename__ = 'categories'
    id = Column(Integer, primary_key=True)
    loc_id = Column(Integer, ForeignKey("locations.id"))
    name = Column(String(255), nullable=False)

Base.metadata.create_all(bind=engine)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()