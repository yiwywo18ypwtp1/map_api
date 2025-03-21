from datetime import datetime, timedelta

from fastapi_mail import FastMail, ConnectionConfig, MessageSchema
from jose import jwt

from config import settings

mail_config = ConnectionConfig(
    MAIL_USERNAME=settings.SMTP_USERNAME,
    MAIL_PASSWORD=settings.SMTP_PASSWORD,
    MAIL_FROM=settings.MAIL_FROM,
    MAIL_PORT=settings.SMTP_PORT,
    MAIL_SERVER=settings.SMTP_SERVER,
    MAIL_STARTTLS=False,
    MAIL_SSL_TLS=False,
    USE_CREDENTIALS=False,
    VALIDATE_CERTS=False,
)

fast_mail = FastMail(mail_config)


def create_reset_token(username: str) -> str:
    expire = datetime.utcnow() + timedelta(minutes=settings.RESET_TOKEN_EXPIRE_MINUTES)
    to_encode = {"sub": username, "exp": expire}
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm="HS256")


async def send_reset_email(email: str, token: str):
    reset_link = f"http://yourapp.com/reset-password?token={token}"
    message = MessageSchema(
        subject="Скидання пароля",
        recipients=[email],
        body=f"Для скидання пароля перейдіть за посиланням: {reset_link}",
        subtype="plain",
    )
    await fast_mail.send_message(message)