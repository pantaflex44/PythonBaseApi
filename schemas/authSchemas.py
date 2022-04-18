#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

from pydantic import BaseModel, Field, validator

from schemas.userSchemas import UserProfile
from schemas.validators import validate_passwords_format, validate_username_format


class TokenSchema(BaseModel):
    access_token: str = Field(...)
    expires: int = Field(...)


class CurrentCredentials(BaseModel):
    current_user: UserProfile = Field(...)
    token: str = Field(...)


class ConnectionState(BaseModel):
    connected: bool = Field(...)


class LoginSchema(BaseModel):
    username: str = Field(...)
    password: str = Field(...)

    @validator('username', allow_reuse=True)
    def username_format(cls, v: str):
        return validate_username_format(v)

    @validator('password', allow_reuse=True)
    def passwords_format(cls, v: str):
        return validate_passwords_format(v)

    class Config:
        orm_mode = True


class UpdateTokenSchema(BaseModel):
    username: str = Field(...)
    current_token: str = Field(...)

    @validator('username', allow_reuse=True)
    def username_format(cls, v: str):
        return validate_username_format(v)

    class Config:
        orm_mode = True
