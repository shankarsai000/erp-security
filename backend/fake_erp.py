from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel
from typing import Optional, List
import time
import base64
import json

fake_erp = FastAPI(
    title="Staging ERP Core Service (Mock)",
    version="1.0.0"
)

# Models
class LoginRequest(BaseModel):
    username: str
    password: str

class OrderCreate(BaseModel):
    customer_id: str
    items: List[str]
    total_amount: float

# In-memory store
ORDERS = {
    101: {"order_id": 101, "customer_id": "cust-882", "items": ["Industrial Widget A", "Bearing Assembly"], "total_amount": 1420.50, "status": "shipped"},
    102: {"order_id": 102, "customer_id": "cust-941", "items": ["Hydraulic Pump v2"], "total_amount": 5890.00, "status": "processing"},
}

USERS = {
    1: {"user_id": 1, "username": "admin", "role": "admin", "email": "admin@erp.internal"},
    2: {"user_id": 2, "username": "sales_john", "role": "sales", "email": "john.doe@erp.internal"},
}

INVENTORY = [
    {"sku": "SKU-9901", "name": "Industrial Widget A", "quantity": 420, "warehouse": "East-1"},
    {"sku": "SKU-9902", "name": "Bearing Assembly", "quantity": 1850, "warehouse": "Central-2"},
    {"sku": "SKU-9903", "name": "Hydraulic Pump v2", "quantity": 34, "warehouse": "West-1"},
]

def make_mock_jwt(sub: str, role: str) -> str:
    header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).decode().rstrip("=")
    payload = base64.urlsafe_b64encode(json.dumps({"sub": sub, "role": role, "exp": int(time.time()) + 3600}).encode()).decode().rstrip("=")
    sig = base64.urlsafe_b64encode(b"simulated_mock_cryptographic_signature").decode().rstrip("=")
    return f"{header}.{payload}.{sig}"

@fake_erp.get("/health")
async def health():
    return {"status": "ok", "service": "staging-erp-backend"}

@fake_erp.post("/api/auth/login")
async def login(req: LoginRequest):
    if req.username in ["admin", "sales_john"] and req.password == "password123":
        token = make_mock_jwt(req.username, "admin" if req.username == "admin" else "sales")
        return {"access_token": token, "token_type": "Bearer", "expires_in": 3600}
    raise HTTPException(status_code=401, detail="Invalid username or password")

@fake_erp.get("/api/orders")
async def get_orders(x_request_id: Optional[str] = Header(None)):
    return {
        "orders": list(ORDERS.values()),
        "total": len(ORDERS),
        "forwarded_request_id": x_request_id
    }

@fake_erp.get("/api/orders/{order_id}")
async def get_order_by_id(order_id: int, x_request_id: Optional[str] = Header(None)):
    if order_id not in ORDERS:
        raise HTTPException(status_code=404, detail="Order not found")
    return {
        "order": ORDERS[order_id],
        "forwarded_request_id": x_request_id
    }

@fake_erp.post("/api/orders")
async def create_order(order: OrderCreate, x_request_id: Optional[str] = Header(None)):
    new_id = max(ORDERS.keys()) + 1 if ORDERS else 100
    record = {
        "order_id": new_id,
        "customer_id": order.customer_id,
        "items": order.items,
        "total_amount": order.total_amount,
        "status": "created"
    }
    ORDERS[new_id] = record
    return {
        "message": "Order created successfully",
        "order": record,
        "forwarded_request_id": x_request_id
    }

@fake_erp.get("/api/users/{user_id}")
async def get_user(user_id: int, x_request_id: Optional[str] = Header(None)):
    if user_id not in USERS:
        raise HTTPException(status_code=404, detail="User not found")
    return {
        "user": USERS[user_id],
        "forwarded_request_id": x_request_id
    }

@fake_erp.get("/api/inventory")
async def get_inventory(x_request_id: Optional[str] = Header(None)):
    return {
        "inventory": INVENTORY,
        "item_count": len(INVENTORY),
        "forwarded_request_id": x_request_id
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(fake_erp, host="0.0.0.0", port=8001)
