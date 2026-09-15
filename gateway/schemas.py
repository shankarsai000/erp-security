from pydantic import BaseModel, Field, field_validator
from typing import List, Optional
import re

class LoginSchema(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, description="Alphanumeric username")
    password: str = Field(..., min_length=6, max_length=128, description="User password")

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        if not re.match(r"^[a-zA-Z0-9_\-\.]+$", v):
            raise ValueError("Username contains invalid characters")
        return v

class OrderCreateSchema(BaseModel):
    customer_id: str = Field(..., min_length=3, max_length=64)
    items: List[str] = Field(..., min_length=1, max_length=50)
    total_amount: float = Field(..., gt=0, lt=10000000.0)

    @field_validator("items")
    @classmethod
    def validate_items(cls, items: List[str]) -> List[str]:
        for item in items:
            if len(item.strip()) == 0 or len(item) > 120:
                raise ValueError("Item names must be between 1 and 120 characters")
        return items

class UserUpdateSchema(BaseModel):
    email: Optional[str] = Field(None, max_length=120)
    phone: Optional[str] = Field(None, max_length=30)
