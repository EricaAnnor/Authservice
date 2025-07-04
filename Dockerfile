FROM python:3.11-slim

WORKDIR /auth

COPY requirements.txt .

RUN pip install --no-cache -r requirements.txt

COPY ./auth ./auth

EXPOSE 8000

CMD ["fastapi", "dev", "auth/main.py", "--host", "0.0.0.0", "--port", "8000"]
