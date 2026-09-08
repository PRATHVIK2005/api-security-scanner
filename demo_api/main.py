from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(
    title="Demo API",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def home():
    return {
        "message": "Demo API is running"
    }


@app.get("/users")
def get_users():
    return [
        {
            "id": 1,
            "name": "Alice",
        },
        {
            "id": 2,
            "name": "Bob",
        },
    ]


@app.get("/products")
def get_products():
    return [
        {
            "id": 1,
            "name": "Laptop",
        }
    ]


@app.post("/users")
def create_user():
    return {
        "message": "User created"
    }
    
@app.get("/admin")
def admin():
    return {
        "message": "Admin panel exposed",
    }
    
@app.get("/debug")
def debug():
    return {
        "debug": True,
        "environment": "development",
    }


@app.get("/api/v0/users")
def get_v0_users():
    return [
        {
            "id": 1,
            "name": "Legacy Alice",
        }
    ]


@app.get("/legacy/users")
def get_legacy_users():
    return [
        {
            "id": 1,
            "name": "Legacy User",
        }
    ]


@app.get("/deprecated/orders")
def get_deprecated_orders():
    return [
        {
            "id": 101,
            "item": "Deprecated Order",
        }
    ]


@app.get("/v1beta/admin")
def get_v1beta_admin():
    return {
        "message": "Beta admin endpoint",
    }


@app.get("/token-test")
def token_test():
    return {
        "token": (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJ1c2VyX2lkIjoxMjN9."
            "abc123signature"
        ),
        "api_key": "abcdefghijklmnop123456",
    }
