#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

from types import MethodType

from fastapi import HTTPException, status

from sqlalchemy import asc, desc

from core.functions import sha512_hash
from core.sql import db_session

from sqlalchemy.orm import Session

from models.authModels import Access, User, Profile, Role

from schemas.authSchemas import AccessSchema, RoleSchema, UserProfile, UserProfileEx


def get_user_ex(filters: list[MethodType]) -> UserProfileEx:
    """Return the extended profile of an user

    Args:
        filters (list[MethodType]): List of models conditions.

    Returns:
        UserProfileEx: Extended profile data
    """
    db: Session = db_session.get()

    user: User = db.query(User).filter(*filters).first()
    if user is None:
        return None

    profile: Profile = db.query(Profile).filter(Profile.id == user.profile_id).first()
    if profile is None:
        return None

    role: Role = db.query(Role).filter(Role.id == user.role_id).first()
    if role is None:
        return None

    return UserProfileEx(**{**profile.__dict__, **role.__dict__, **user.__dict__})


def get_user(filters: list[MethodType]) -> UserProfile:
    """Return the profile of an user

    Args:
        filters (list[MethodType]): List of models conditions.

    Returns:
        UserProfile: Profile data
    """
    db: Session = db_session.get()

    userEx: UserProfileEx = get_user_ex(filters)
    if userEx is None:
        return None

    return UserProfile(**userEx.__dict__)


def get_users(offset: int = 0, limit: int = 1) -> list[UserProfile]:
    """Return all users profile

    Args:
        offset (int, optional): Start index. Defaults to 0.
        limit (int, optional): Quantity returned. Defaults to 1.

    Returns:
        list[UserProfile]: List of all users profile
    """
    db: Session = db_session.get()

    users: list[User] = db.query(User).offset(offset).limit(limit).all()
    usersList: list[UserProfile] = []

    for item in users:
        user: User = get_user([User.id == item.id])
        if user is not None:
            usersList.append(user)

    return usersList


def username_exists(username: str) -> bool:
    """Return if username exists

    Args:
        username (str): Username

    Returns:
        bool: True, username exists, else, False
    """
    db: Session = db_session.get()

    user: User = db.query(User).filter(User.username.like(username.strip())).first()
    if user is not None:
        return True

    return False


def create_user(username: str, password: str, role_id: int) -> UserProfile:
    """Create new user

    Args:
        username (str): The unique username
        password (str): The secure password
        role_id (int): A role ID

    Returns:
        UserProfile: The new user profile
    """
    db: Session = db_session.get()

    role: Role = get_role([Role.id == role_id])
    if role is None:
        return None

    profile: Profile = Profile(display_name=username)
    user: User = User(username=username, hashed_password=sha512_hash(password),
                      is_activated=False, is_blocked=False, profile=profile, role=role)

    try:
        db.add(user)
        db.commit()
        db.refresh(user)
    except:
        return None

    user_profile: UserProfile = get_user([User.id == user.id])
    if user_profile is None:
        return None

    return user_profile


# ----------------------------- ACCESS -------------------------

def get_access(filters: list[MethodType]) -> Access:
    """Return an access from a filter

    Args:
        filters (list[MethodType]): List of models conditions.

    Returns:
        Access: The access found
    """
    db: Session = db_session.get()

    access: Access = db.query(Access).filter(*filters).first()
    return access


def get_accesses(offset: int = 0, limit: int = 1) -> list[Access]:
    """Return list of accesses

    Args:
        offset (int, optional): Start index. Defaults to 0.
        limit (int, optional): Quantity returned. Defaults to 1.

    Returns:
        list[Access]: List of found accesses
    """
    db: Session = db_session.get()

    accesses: list[Access] = db.query(Access).offset(offset).limit(limit).all()
    return accesses


def get_accesses_for_role(role_id: int, offset: int = 0, limit: int = 1) -> list[Access]:
    """Return list of accesses for a specified role

    Args:
        role_id (int): The role ID
        offset (int, optional): Start index. Defaults to 0.
        limit (int, optional): Quantity returned. Defaults to 1.

    Returns:
        list[Access]: List of found access    print(role)es
    """
    db: Session = db_session.get()

    accesses: list[Access] = []
    accesses_found: list[Access] = db.query(Access).offset(offset).limit(limit).all()
    for access in accesses_found:
        if role_id in access.role_ids:
            accesses.append(access)

    return accesses


def add_role_to_access(access_id: int, role_id: int) -> Access:
    """Add a role to an access

    Args:
        access_id (int): Access rule identifier
        role_id (int): Role identifier

    Returns:
        Access: Updated access
    """
    db: Session = db_session.get()

    access: Access = get_access([Access.id == access_id])
    if access is None:
        return None

    role: Role = get_role([Role.id == role_id])
    if role is None:
        return None

    if role.id not in access.role_ids:
        access.role_ids = access.role_ids + [role.id]
        db.add(access)
        db.commit()
        db.refresh(access)

    return access


def add_roles_to_access(access_id: int, role_ids: list[int]) -> Access:
    """Add roles to an access

    Args:
        access_id (int): Access rule identifier
        role_ids (list[int]): List of role identifiers

    Returns:
        Access: Updated access
    """
    db: Session = db_session.get()

    access: Access = get_access([Access.id == access_id])
    if access is None:
        return None

    for role_id in role_ids:
        role: Role = get_role([Role.id == role_id])
        if role is None:
            return None

        if role.id not in access.role_ids:
            access.role_ids = access.role_ids + [role.id]

    db.add(access)
    db.commit()
    db.refresh(access)

    return access


def remove_role_to_access(access_id: int, role_id: int) -> Access:
    """Remove a role to an access

    Args:
        access_id (int): Access rule identifier
        role_id (int): Role identifier

    Returns:
        Access: Updated access
    """
    db: Session = db_session.get()

    access: Access = get_access([Access.id == access_id])
    if access is None:
        return None

    role: Role = get_role([Role.id == role_id])
    if role is None:
        return None

    if role.id in access.role_ids and len(access.role_ids) > 1:
        role_ids = access.role_ids
        role_ids.remove(role_id)
        db.query(Access).filter(Access.id == access.id).update({Access.role_ids: role_ids})
        db.commit()
        db.refresh(access)

    return access


def remove_roles_to_access(access_id: int, role_ids: list[int]) -> Access:
    """Remove roles to an access

    Args:
        access_id (int): Access rule identifier
        role_ids (list[int]): List of role identifiers

    Returns:
        Access: Updated access
    """
    db: Session = db_session.get()

    access: Access = get_access([Access.id == access_id])
    if access is None:
        return None

    role_ids = access.role_ids
    for role_id in role_ids:
        role: Role = get_role([Role.id == role_id])
        if role is None:
            return None

        if role.id in access.role_ids and len(access.role_ids) > 1:
            role_ids.remove(role_id)

    db.query(Access).filter(Access.id == access.id).update({Access.role_ids: role_ids})
    db.commit()
    db.refresh(access)

    return access


def access_to_schema(access: Access) -> AccessSchema:
    """Convert an access model to his json schema

    Args:
        access (Access): Access model to convert

    Returns:
        AccessSchema: Access schema
    """
    roles: list[RoleSchema] = []
    for role_id in access.role_ids:
        role: Role = get_role([Role.id == role_id])
        if role is not None:
            roles.append(RoleSchema(**role.__dict__))

    return AccessSchema(id=access.id,
                        route_name=access.route_name,
                        route_comment=access.route_comment,
                        allowed_roles=roles)


# ------------------------------ ROLE --------------------------

def get_role(filters: list[MethodType]) -> Role:
    """Return a role from a filter

    Args:
        filters (list[MethodType]): List of role model conditions.

    Returns:
        Role: The role found
    """
    db: Session = db_session.get()

    role: Role = db.query(Role).filter(*filters).first()
    return role


def get_higher_role() -> Role:
    """Return the higher role

    Returns:
        Role: The higher role
    """
    db: Session = db_session.get()

    role: Role = db.query(Role).order_by(desc(Role.role_level)).limit(1).first()
    return role


def get_higher_role_level() -> int:
    """Return the higher role level

    Returns:
        int: The higher role level
    """
    higher_role: Role = get_higher_role()
    return higher_role.role_level


def get_lower_role() -> Role:
    """Return the lower role

    Returns:
        Role: The lower role
    """
    db: Session = db_session.get()

    role: Role = db.query(Role).order_by(asc(Role.role_level)).limit(1).first()
    return role


def get_lower_role_level() -> int:
    """Return the lower role level

    Returns:
        int: The lower role level
    """
    lower_role: Role = get_lower_role()
    return lower_role.role_level


def get_roles(offset: int = 0, limit: int = 1) -> list[Role]:
    """Return list of roles

    Args:
        offset (int, optional): Start index. Defaults to 0.
        limit (int, optional): Quantity returned. Defaults to 1.

    Returns:
        list[Role]: List of found roles
    """
    db: Session = db_session.get()

    roles: list[Role] = db.query(Role).offset(offset).limit(limit).all()
    return roles
