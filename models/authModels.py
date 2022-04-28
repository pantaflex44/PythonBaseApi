#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

import json

from inspect import signature

from core import settings

from fastapi import FastAPI

from core.functions import print_info, sha512_hash
from core.sql import Base

from sqlalchemy import Boolean, Column, ForeignKey, Integer, String, DateTime, Text, Enum, TypeDecorator, desc
from sqlalchemy.orm import Session, relationship, backref
from sqlalchemy.sql import func

from schemas.authSchemas import CurrentCredentials


class ArrayType(TypeDecorator):
    """SqlAlchemy custum type.
    """
    impl = Text(length=65535)
    cache_ok = True

    def process_bind_param(self, value, dialect):
        stringify = json.dumps(value)
        return stringify

    def process_result_value(self, value, dialect):
        tolist = json.loads(value)
        return tolist


class User(Base):
    """The User database model
    """
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(255), unique=True, index=True)
    hashed_password = Column(String(255))
    is_activated = Column(Boolean, default=False)
    is_blocked = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    role_id = Column(Integer, ForeignKey('roles.id'))
    role = relationship("Role", backref=backref("users"), primaryjoin="User.role_id == Role.id")
    profile_id = Column(Integer, ForeignKey('users_profiles.id'))
    profile = relationship("Profile", backref=backref("users", uselist=False), order_by="User.username",
                           primaryjoin="User.profile_id == Profile.id", cascade="all, delete")


class Profile(Base):
    """The Profil database model
    """
    __tablename__ = "users_profiles"
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    display_name = Column(String(255), default="")
    email = Column(String(255), unique=True, index=True, default="")
    avatar = Column(String(255), default=settings.default_avatar_url)
    description = Column(Text, default="")


class Role(Base):
    """The Role database model
    """
    __tablename__ = "roles"
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    role_name = Column(String(255), unique=True, index=True)
    role_level = Column(Integer)


class Access(Base):
    """The Access database model
    """
    __tablename__ = "accesses"
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    route_name = Column(String(255), unique=True, index=True)
    route_comment = Column(Text)
    role_ids = Column(ArrayType, default=[])


class ResetTokens(Base):
    """Reset tokens list
    """
    __tablename__ = "reset_tokens"
    reset_key = Column(String(255), primary_key=True, index=True)
    expires = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, primary_key=True, index=True)


def up(db: Session, app: FastAPI):
    """Called with database installation

    Args:
        db (Session): Database session
        app (FastAPI): Application instance
    """
    db.execute("DELETE FROM users;")
    db.execute("DELETE FROM users_profiles;")
    db.execute("DELETE FROM accesses;")
    db.execute("DELETE FROM roles;")

    for name, level in settings.default_roles.items():
        db.add(Role(role_name=name, role_level=level))
        print_info(f"- '{name} ({level})' role created.")
    db.commit()
    print_info("Roles created successfully.")
    print("")

    higher_role: Role = db.query(Role).order_by(desc(Role.role_level)).limit(1).first()
    for route in app.routes:
        if 'endpoint' in route.__dict__.keys():
            if len(route.name) > 6 and route.name[:6].lower() == "route_":
                route_name = route.name[6:]
                route_comment = route.endpoint.__doc__.splitlines()[0] if route.endpoint.__doc__ is not None else ""
                params = signature(route.endpoint).parameters
                for param in params:
                    if params[param].annotation is CurrentCredentials:
                        access: Access = Access(route_name=route_name,
                                                route_comment=route_comment,
                                                role_ids=[higher_role.id])
                        db.add(access)
                        print_info(f"- Restricted route access '{route_name}' authorized for the higher role.")
    db.commit()
    print_info("All restricted routes accesses successfully created.")
    print("")

    profile = Profile(email="pantaflex@hotmail.fr", display_name="Administrator",
                      description="The first and unique administrator account.")
    user = User(username="administrator", hashed_password=sha512_hash("Admin1234!"),
                is_activated=True, is_blocked=False, profile=profile, role=higher_role)
    db.add(user)
    db.commit()
    print_info("Default administrator account created: login: 'administrator', password: 'Admin1234!'.")
    print("")
