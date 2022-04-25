#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

from types import MethodType

from fastapi import Query

from sqlalchemy import asc, desc

from core.functions import sha512_hash
from core.sql import db_session

from sqlalchemy.orm import Session

from models.authModels import Access, User, Profile, Role

from schemas.authSchemas import AccessSchema, RoleSchema, UserProfile, UserProfileEx


def get_allowed_levels(route_name: str) -> list[int]:
    """Get route allowed levels

    Args:
        route_name (str): Name of the route (started with 'route_'...)

    Returns:
        list[int]: List of allowed levels
    """
    db: Session = db_session.get()

    allowed_levels: list[int] = []

    if len(route_name) > 6 and route_name[:6].lower() == "route_":
        route_name = route_name[6:]

        access: Access = db.query(Access).filter(Access.route_name.like(route_name)).first()
        if access is not None:
            for id in access.role_ids:
                role: Role = db.query(Role).filter(Role.id == id).first()
                if role is None:
                    continue
                allowed_levels.append(role.role_level)

            allowed_levels = sorted(allowed_levels, reverse=True)

    return allowed_levels


def is_allowed_level(route_name: str, wanted_level: int) -> bool:
    """Is a wnted level allowed for a route

    Args:
        route_name (str): Name of the route (started with 'route_'...)
        wanted_level (int): Wanted level to verify

    Returns:
        bool: True, wanted level is allowed, else, False
    """
    allowed_levels: list[int] = get_allowed_levels(route_name)
    higher_role_level: int = get_higher_role_level()
    for level in allowed_levels:
        if wanted_level == level or wanted_level == higher_role_level:
            return True

    return False


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


def get_users(filter: list[MethodType] = None, offset: int = 0, limit: int = 1) -> list[UserProfile]:
    """Return all users profile

    Args:
        offset (int, optional): Start index. Defaults to 0.
        limit (int, optional): Quantity returned. Defaults to 1.

    Returns:
        list[UserProfile]: List of all users profile
    """
    db: Session = db_session.get()

    users_query: Query = db.query(User)

    if filter is not None:
        users_query = users_query.filter(*filter)

    users: list[User] = users_query.offset(offset).limit(limit).all()

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


def update_username(id: int, username: str) -> UserProfile:
    """Update username

    Args:
        id (int): User ID
        username (str): New username

    Returns:
        UserProfile: The updated user profile
    """
    db: Session = db_session.get()

    user: User = db.query(User).filter(User.id == id).first()
    if user is None:
        return None

    db.query(User).filter(User.id == user.id).update({User.username: username})
    db.commit()

    user_profile: UserProfile = get_user([User.id == user.id])
    if user_profile is None:
        return None

    return user_profile


def update_active_state(id: int, state: bool) -> UserProfile:
    """Update active state

    Args:
        id (int): User ID
        state (bool): New active state

    Returns:
        UserProfile: The updated user profile
    """
    db: Session = db_session.get()

    user: User = db.query(User).filter(User.id == id).first()
    if user is None:
        return None

    db.query(User).filter(User.id == user.id).update({User.is_activated: state})
    db.commit()

    user_profile: UserProfile = get_user([User.id == user.id])
    if user_profile is None:
        return None

    return user_profile


def update_blocked_state(id: int, state: bool) -> UserProfile:
    """Update blocked state

    Args:
        id (int): User ID
        state (bool): New blocked state

    Returns:
        UserProfile: The updated user profile
    """
    db: Session = db_session.get()

    user: User = db.query(User).filter(User.id == id).first()
    if user is None:
        return None

    db.query(User).filter(User.id == user.id).update({User.is_blocked: state})
    db.commit()

    user_profile: UserProfile = get_user([User.id == user.id])
    if user_profile is None:
        return None

    return user_profile


def update_user_profile(id: int, data: dict) -> UserProfile:
    """Update user profile

    Args:
        id (int): User ID
        data (dict): Profile data

    Returns:
        UserProfile: The updated user profile
    """
    db: Session = db_session.get()

    user: User = db.query(User).filter(User.id == id).first()
    if user is None:
        return None

    db.query(Profile).filter(Profile.id == user.profile_id).update(data)
    db.commit()

    user_profile: UserProfile = get_user([User.id == user.id])
    if user_profile is None:
        return None

    return user_profile


def delete_user(id: int) -> bool:
    """Delete an user

    Args:
        id (int): The User ID

    Returns:
        bool: True, user is deleted, else, False
    """
    db: Session = db_session.get()

    user: User = db.query(User).filter(User.id == id).first()
    if user is None:
        return False

    role: Role = get_role([Role.id == user.role_id])
    if role is None:
        return False

    if role.role_level >= get_higher_role_level():
        nb_higher_roles: int = db.query(Role).filter([Role.role_level >= role.role_level]).count()
        if nb_higher_roles <= 1:
            return False

    db.delete(user)
    db.commit()

    return True


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

        try:
            db.add(access)
            db.commit()
            db.refresh(access)
        except:
            return None

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

    try:
        db.add(access)
        db.commit()
        db.refresh(access)
    except:
        return None

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
        try:
            role_ids = access.role_ids
            role_ids.remove(role_id)

            db.query(Access).filter(Access.id == access.id).update({Access.role_ids: role_ids})
            db.commit()
            db.refresh(access)
        except:
            return None

    return access


def remove_role_to_all_access(role_id: int):
    """Remove a role to all access

    Args:
        role_id (int): Role identifier
    """
    db: Session = db_session.get()

    accesses: list[Access] = get_accesses()
    for access in accesses:
        if role_id in access.role_ids and len(access.role_ids) > 1:
            role_ids = access.role_ids
            role_ids.remove(role_id)

            if len(role_ids) == 0:
                higher_role: Role = get_higher_role()
                if higher_role is None:
                    continue

                role_ids = role_ids + higher_role.id

            db.query(Access).filter(Access.id == access.id).update({Access.role_ids: role_ids})
            db.commit()
            db.refresh(access)


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

    try:
        db.query(Access).filter(Access.id == access.id).update({Access.role_ids: role_ids})
        db.commit()
        db.refresh(access)
    except:
        return None

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


def role_level_exists(level: int) -> bool:
    """Role level exists

    Args:
        level (int): Role level

    Returns:
        bool: True, role level exists, else, False
    """
    db: Session = db_session.get()

    role: Role = db.query(Role).filter(Role.role_level == level).limit(1).first()
    return role is not None


def role_name_exists(name: str) -> bool:
    """Role name exists

    Args:
        name (str): Role name

    Returns:
        bool: True, role name exists, else, False
    """
    db: Session = db_session.get()

    role: Role = db.query(Role).filter(Role.role_name.like(name)).limit(1).first()
    return role is not None


def create_role(role_name: str, role_level: int) -> Role:
    """Create new role

    Args:
        role_name (str): Role name
        role_level (int): Role level

    Returns:
        Role: New created role
    """
    db: Session = db_session.get()

    role: Role = Role(role_name=role_name, role_level=role_level)

    try:
        db.add(role)
        db.commit()
        db.refresh(role)
    except:
        return None

    return role


def update_role(role_id: int, role_name: str = None, role_level: int = None) -> Role:
    """Update role

    Args:
        role_id (int): Role ID to update.
        role_name (str): Role name. Default to None.
        role_level (int): Role level. Default to None.

    Returns:
        Role: Updated Role
    """
    db: Session = db_session.get()

    role: Role = get_role([Role.id == role_id])
    if role is None:
        return None

    if role_name is None:
        role_name = role.role_name

    if role_level is None:
        role_level = role.role_level

    try:
        db.query(Role).filter(Role.id == role_id).update({Role.role_name: role_name, Role.role_level: role_level})
        db.commit()
        db.refresh(role)
    except:
        return None

    return role


def delete_role(role_id: int) -> bool:
    """Delete a Role

    Args:
        role_id (int): Role ID to delete

    Returns:
        bool: True, Role is deleted, else, False
    """
    db: Session = db_session.get()

    role: Role = get_role([Role.id == role_id])
    if role is None:
        return False

    db.delete(role)
    db.commit()

    return True
