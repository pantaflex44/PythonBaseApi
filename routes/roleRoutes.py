#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

from typing import Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Path, Query, status
from core import settings

from core.authBearer import access

from schemas.authSchemas import CurrentCredentials, RoleBase, RoleSchema, UserProfile

from models.methods.authMethods import create_role, delete_role, get_role, get_roles, get_users, remove_role_to_access, remove_role_to_all_access, role_level_exists, role_name_exists, update_role
from models.authModels import Role, User


router: APIRouter = APIRouter(prefix="/roles", tags=["roles"])


@router.get('/list', status_code=status.HTTP_200_OK, response_model=list[RoleSchema])
async def route_get_all_roles(offset: Optional[int] = Query(0, ge=0),
                              limit: Optional[int] = Query(100, ge=1),
                              credentials: CurrentCredentials = Depends(access)):
    """Get all user roles

    Args:
        offset (Optional[int], optional): Start index. Defaults to Query(0, ge=0).
        limit (Optional[int], optional): Quantity of returned rows. Defaults to Query(100, ge=1).
        credentials (CurrentCredentials, optional): Depend bearer credentials. Defaults to Depends(access).

    Returns:
        list[RoleSchema]: List of users roles
    """
    roles_schemas: list[RoleSchema] = []
    roles: list[Role] = get_roles(offset, limit)
    for role in roles:
        roles_schemas.append(RoleSchema(**role.__dict__))

    return roles_schemas


@router.get('/list_defaults', status_code=status.HTTP_200_OK, response_model=list[RoleBase])
async def route_get_all_default_roles(credentials: CurrentCredentials = Depends(access)):
    """Get all default user roles

    Args:
        credentials (CurrentCredentials, optional): Depend bearer credentials. Defaults to Depends(access).

    Returns:
        list[RoleBase]: List of users roles
    """
    roles_bases: list[RoleBase] = []
    for name, level in settings.default_roles.items():
        roles_bases.append(RoleBase(role_name=name, role_level=level))

    return roles_bases


@router.get('/get/{id}', status_code=status.HTTP_200_OK, response_model=RoleSchema)
async def route_get_unique_role(id: int = Path(..., ge=1),
                                credentials: CurrentCredentials = Depends(access)):
    """Get a role from his ID

    Args:
        id (int, optional): Access rule ID. Defaults to Path(..., ge=1).
        credentials (CurrentCredentials, optional): Depend bearer credentials. Defaults to Depends(access).

    Raises:
        HTTPException: HTTP_404_NOT_FOUND - Role not found

    Returns:
        RoleSchema: Role found
    """
    role: Role = get_role([Role.id == id])
    if role is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="Role not found")

    return RoleSchema(**role.__dict__)


@router.post('/create', status_code=status.HTTP_200_OK, response_model=RoleSchema)
async def route_create_role(create: RoleBase = Body(...),
                            credentials: CurrentCredentials = Depends(access)):
    """Create new role

    Args:
        create (RoleBase, optional): New role data. Defaults to Body(...).
        credentials (CurrentCredentials, optional): Depend bearer credentials. Defaults to Depends(access).

    Raises:
        HTTPException: HTTP_400_BAD_REQUEST - Role name already exists
        HTTPException: HTTP_400_BAD_REQUEST - Role level already exists

    Returns:
        RoleSchema: Role created
    """
    if role_name_exists(create.role_name):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Role name already exists")

    if role_level_exists(create.role_level):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Role level already exists")

    role: Role = create_role(create.role_name, create.role_level)

    return RoleSchema(**role.__dict__)


@router.put('/update/{id}', status_code=status.HTTP_200_OK, response_model=RoleSchema)
async def route_update_role(id: int = Path(..., ge=1),
                            update: RoleBase = Body(...),
                            credentials: CurrentCredentials = Depends(access)):
    """Update a Role

    Args:
        id (int, optional): Role ID to update. Defaults to Path(..., ge=1).
        update (RoleBase, optional): Update data. Defaults to Body(...).
        credentials (CurrentCredentials, optional): Depend bearer credentials. Defaults to Depends(access).

    Raises:
        HTTPException: HTTP_400_BAD_REQUEST - Role name already exists
        HTTPException: HTTP_400_BAD_REQUEST - Role level already exists
        HTTPException: HTTP_404_NOT_FOUND - Role not found

    Returns:
        RoleSchema: Updated Role
    """
    if role_name_exists(update.role_name):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Role name already exists")

    if role_level_exists(update.role_level):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Role level already exists")

    role: Role = update_role(id, update.role_name, update.role_level)
    if role is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="Role not found")

    return RoleSchema(**role.__dict__)


@router.delete('/delete/{id}', status_code=status.HTTP_200_OK, response_model=bool)
async def route_delete_role(id: int = Path(..., ge=1),
                            credentials: CurrentCredentials = Depends(access)):
    """Delete a Role

    Args:
        id (int, optional): Role ID to delete. Defaults to Path(..., ge=1).
        credentials (CurrentCredentials, optional): Depend bearer credentials. Defaults to Depends(access).

    Returns:
        bool: True, Role is deleted, else, False
    """
    role: Role = get_role([Role.id == id])
    if role is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="Role not found")

    users: list[UserProfile] = get_users(filter=[User.role_id == role.id])
    if len(users) > 0:
        raise HTTPException(status_code=status.HTTP_405_METHOD_NOT_ALLOWED,
                            detail="First delete all user accounts that subscribe to this role")

    deleted: bool = delete_role(id)
    if deleted:
        remove_role_to_all_access(id)

    return deleted
