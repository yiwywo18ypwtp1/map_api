# Використовуємо офіційний образ Python
FROM python:3.9-slim

# Встановлюємо робочу директорію
WORKDIR /app

# Копіюємо файли залежностей
COPY requirements.txt .

# Встановлюємо залежності
RUN pip install --no-cache-dir -r requirements.txt

# Копіюємо весь проект
COPY . .

# Встановлюємо змінну середовища для Python
ENV PYTHONUNBUFFERED=1

# Вказуємо порт, який буде використовувати FastAPI
EXPOSE 8000

# Команда для запуску FastAPI
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]