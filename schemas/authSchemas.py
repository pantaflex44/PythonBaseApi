#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

from datetime import datetime
from time import time

from core import settings

from pydantic import BaseModel, EmailStr, Field, validator

from schemas.validators.authValidators import (
    validate_avatar_format,
    validate_description_format,
    validate_display_name_format,
    validate_email_format,
    validate_passwords_format,
    validate_role_level_format,
    validate_role_name_format,
    validate_username_format
)


class UserBaseMin(BaseModel):
    username: str = Field(...)
    is_activated: bool = Field(False)
    is_blocked: bool = Field(False)

    @validator('username', allow_reuse=True)
    def username_format(cls, v: str):
        return validate_username_format(v)


class UserBase(UserBaseMin):
    created_at: datetime = Field(datetime.now())
    updated_at: datetime = Field(datetime.now())


class UserBaseEx(UserBase):
    hashed_password: str = Field(...)


class User(UserBase):
    id: int = Field(...)

    class Config:
        orm_mode = True


class ProfileBase(BaseModel):
    display_name: str = Field("")
    email: str = EmailStr("")
    avatar: str = Field("")
    description: str = Field("")

    @validator('display_name', allow_reuse=True)
    def display_name_format(cls, v: str):
        return validate_display_name_format(v)

    @validator('email', allow_reuse=True)
    def email_format(cls, v: str):
        return validate_email_format(v)

    @validator('avatar', allow_reuse=True)
    def avatar_format(cls, v: str):
        return validate_avatar_format(v)

    @validator('description', allow_reuse=True)
    def description_format(cls, v: str):
        return validate_description_format(v)


class ProfileSchema(ProfileBase):
    id: int = Field(...)

    class Config:
        orm_mode = True


class RoleBase(BaseModel):
    role_name: str = Field(...)
    role_level: int = Field(...)

    @validator('role_name', allow_reuse=True)
    def role_name_format(cls, v: str):
        return validate_role_name_format(v)

    @validator('role_level', allow_reuse=True)
    def role_level_format(cls, v: int):
        return validate_role_level_format(v)


class RoleSchema(RoleBase):
    id: int = Field(...)

    class Config:
        orm_mode = True


class AccessSchemaMin(BaseModel):
    id: int = Field(...)
    route_name: str = Field(...)
    route_comment: str = Field(...)

    class Config:
        orm_mode = True


class AccessSchema(AccessSchemaMin):
    allowed_roles: list[RoleSchema] = Field(...)

    class Config:
        orm_mode = True


class RoleAccessSchema(BaseModel):
    role: RoleSchema = Field(...)
    accesses: list[AccessSchemaMin] = Field(...)

    class Config:
        orm_mode = True


class AddRemoveRoleSchema(BaseModel):
    role_id: int = Field(..., ge=1)

    class Config:
        orm_mode = True


class AddRemoveRolesSchema(BaseModel):
    role_ids: list[int] = Field(...)

    class Config:
        orm_mode = True


class UserProfile(UserBase, ProfileBase, RoleBase):
    id: int = Field(...)

    class Config:
        orm_mode = True


class UserProfileEx(UserBaseEx, ProfileBase, RoleBase):
    id: int = Field(...)

    class Config:
        orm_mode = True


class CreateSchema(BaseModel):
    username: str = Field("")
    password: str = Field("")
    email: str = EmailStr("")
    role_id: int = Field(1, ge=1)

    @validator('username', allow_reuse=True)
    def username_format(cls, v: str):
        return validate_username_format(v)

    @validator('password', allow_reuse=True)
    def passwords_format(cls, v: str):
        return validate_passwords_format(v)

    class Config:
        orm_mode = True


class UpdateUsernameSchema(BaseModel):
    username: str = Field("")
    #is_activated: bool = Field(False)
    #is_blocked: bool = Field(False)

    @validator('username', allow_reuse=True)
    def username_format(cls, v: str):
        return validate_username_format(v)

    class Config:
        orm_mode = True


class UpdateStateSchema(BaseModel):
    state: bool = Field(False)

    class Config:
        orm_mode = True


class TokenSchema(BaseModel):
    access_token: str = Field(...)
    expires: int = Field(...)


class CurrentCredentials(BaseModel):
    current_user: UserProfile = Field(...)
    token: str = Field(...)


class ConnectionState(BaseModel):
    connected: bool = Field(...)


class LoginSchema(BaseModel):
    username: str = Field("")
    password: str = Field("")

    @validator('username', allow_reuse=True)
    def username_format(cls, v: str):
        return validate_username_format(v)

    @validator('password', allow_reuse=True)
    def passwords_format(cls, v: str):
        return validate_passwords_format(v)

    class Config:
        orm_mode = True


class PasswordResetSchema(BaseModel):
    username: str = Field("")
    email: str = EmailStr("")

    @validator('username', allow_reuse=True)
    def username_format(cls, v: str):
        return validate_username_format(v)

    @validator('email', allow_reuse=True)
    def email_format(cls, v: str):
        return validate_email_format(v)

    class Config:
        orm_mode = True


class PasswordResetTokenSchema(BaseModel):
    reset_token: str = Field(...)
    expires: int = Field(int(time()))


class UpdateTokenSchema(BaseModel):
    username: str = Field("")
    current_token: str = Field("")

    @validator('username', allow_reuse=True)
    def username_format(cls, v: str):
        return validate_username_format(v)

    class Config:
        orm_mode = True
