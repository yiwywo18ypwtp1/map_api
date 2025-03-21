from pydantic import EmailStr
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    SMTP_SERVER: str = "localhost"  # Локальний SMTP-сервер
    SMTP_PORT: int = 1025  # Порт локального сервера
    SMTP_USERNAME: str = ""  # Не потрібно для локального сервера
    SMTP_PASSWORD: str = ""  # Не потрібно для локального сервера
    MAIL_FROM: EmailStr = "negalapetrovna77@gmail.com"  # Коректна email-адреса
    SECRET_KEY: str = "your-secret-key"
    RESET_TOKEN_EXPIRE_MINUTES: int = 30

    class Config:
        env_file = ".env"

settings = Settings()