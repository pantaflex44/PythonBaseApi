#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

from typing import Optional

from core import settings
from core.authBearer import access

from fastapi import (
    Body,
    Depends,
    Path,
    Query,
    status,
    APIRouter,
    HTTPException
)

from models.methods.authMethods import (
    access_to_schema,
    add_role_to_access,
    add_roles_to_access,
    get_access, get_accesses,
    get_accesses_for_role,
    get_role,
    remove_role_to_access,
    remove_roles_to_access
)
from models.authModels import Access, Role

from schemas.authSchemas import CurrentCredentials
from schemas.authSchemas import (
    AccessSchema,
    AccessSchemaMin,
    AddRemoveRoleSchema,
    AddRemoveRolesSchema,
    RoleAccessSchema,
    RoleSchema
)


router: APIRouter = APIRouter(prefix="/accesses", tags=["accesses"])


@router.get('/list', status_code=status.HTTP_200_OK, response_model=list[AccessSchema])
async def route_get_all_accesses(offset: Optional[int] = Query(0, ge=0),
                                 limit: Optional[int] = Query(100, ge=1),
                                 credentials: CurrentCredentials = Depends(access)):
    """Get all accesses rules

    Args:
        offset (Optional[int], optional): Start index. Defaults to Query(0, ge=0).
        limit (Optional[int], optional): Quantity of returned rows. Defaults to Query(100, ge=1).
        credentials (CurrentCredentials, optional): Depend bearer credentials. Defaults to Depends(access).

    Returns:
        list[AccessSchema]: List of accesses rules
    """
    accesses_schemas: list[AccessSchema] = []
    accesses: list[Access] = get_accesses(offset, limit)
    for access in accesses:
        accesses_schemas.append(access_to_schema(access))

    return accesses_schemas


@router.get('/get/{id}', status_code=status.HTTP_200_OK, response_model=AccessSchema)
async def route_get_unique_access(id: int = Path(..., ge=1),
                                  credentials: CurrentCredentials = Depends(access)):
    """Get an access rule from her ID

    Args:
        id (int, optional): Access rule ID. Defaults to Path(..., ge=1).
        credentials (CurrentCredentials, optional): Depend bearer credentials. Defaults to Depends(access).

    Raises:
        HTTPException: HTTP_404_NOT_FOUND - Access not found

    Returns:
        AccessSchema: Access found
    """
    access: Access = get_access([Access.id == id])
    if access is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="Access not found")

    return access_to_schema(access)


@router.get('/list_by_role/{role_id}', status_code=status.HTTP_200_OK, response_model=RoleAccessSchema)
async def route_get_all_accesses_for_role(role_id: int = Path(..., ge=1),
                                          offset: Optional[int] = Query(0, ge=0),
                                          limit: Optional[int] = Query(100, ge=1),
                                          credentials: CurrentCredentials = Depends(access)):
    """Get accesses rules of role

    Args:
        role_id (int, optional): Role ID to inspect. Defaults to Path(..., ge=1).
        offset (Optional[int], optional): Start index. Defaults to Query(0, ge=0).
        limit (Optional[int], optional): Quantity of returned data. Defaults to Query(100, ge=1).
        credentials (CurrentCredentials, optional): Depend bearer credentials. Defaults to Depends(access).

    Raises:
        HTTPException: HTTP_404_NOT_FOUND - Role not found

    Returns:
        RoleAccessSchema: Role and Accesses data
    """
    role: Role = get_role([Role.id == role_id])
    if role is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="Role not found")

    role_schema: RoleSchema = RoleSchema(**role.__dict__)

    accesses_schemas: list[AccessSchemaMin] = []
    accesses: list[Access] = get_accesses_for_role(role.id, offset, limit)
    for access in accesses:
        accesses_schemas.append(AccessSchemaMin(**access.__dict__))

    return RoleAccessSchema(role=role_schema, accesses=accesses_schemas)


@router.put('/{access_id}/add_role', status_code=status.HTTP_200_OK, response_model=AccessSchema)
async def route_add_role_to_access(access_id: int = Path(..., ge=1),
                                   add: AddRemoveRoleSchema = Body(...),
                                   credentials: CurrentCredentials = Depends(access)):
    """Associate role to an access

    Args:
        access_id (int, optional): Access identifier. Defaults to Path(..., ge=1).
        add (AddRemoveRoleSchema, optional): Role ID to associate. Defaults to Body(...).
        credentials (CurrentCredentials, optional): Depend bearer credentials. Defaults to Depends(access).

    Raises:
        HTTPException: HTTP_404_NOT_FOUND - Access or Role not found

    Returns:
        AccessSchema: Updated access
    """
    access: Access = add_role_to_access(access_id, add.role_id)
    if access is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="Access or Role not found")

    return access_to_schema(access)


@router.put('/{access_id}/add_roles', status_code=status.HTTP_200_OK, response_model=AccessSchema)
async def route_add_roles_to_access(access_id: int = Path(..., ge=1),
                                    add: AddRemoveRolesSchema = Body(...),
                                    credentials: CurrentCredentials = Depends(access)):
    """Associate roles to an access

    Args:
        access_id (int, optional): Access identifier. Defaults to Path(..., ge=1).
        add (AddRemoveRolesSchema, optional): List of role IDs to associate. Defaults to Body(...).
        credentials (CurrentCredentials, optional): Depend bearer credentials. Defaults to Depends(access).

    Raises:
        HTTPException: HTTP_404_NOT_FOUND - Access or Role not found

    Returns:
        AccessSchema: Updated access
    """
    access: Access = add_roles_to_access(access_id, add.role_ids)
    if access is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="Access or Role not found")

    return access_to_schema(access)


@router.put('/{access_id}/remove_role', status_code=status.HTTP_200_OK, response_model=AccessSchema)
async def route_remove_role_to_access(access_id: int = Path(..., ge=1),
                                      remove: AddRemoveRoleSchema = Body(...),
                                      credentials: CurrentCredentials = Depends(access)):
    """Dissociate role to an access

    Args:
        access_id (int, optional): Access identifier. Defaults to Path(..., ge=1).
        remove (AddRemoveRoleSchema, optional): Role ID to remove. Defaults to Body(...).
        credentials (CurrentCredentials, optional): Depend bearer credentials. Defaults to Depends(access).

    Raises:
        HTTPException: HTTP_404_NOT_FOUND - Access or Role not found

    Returns:
        AccessSchema: Updated access
    """
    access: Access = remove_role_to_access(access_id, remove.role_id)
    if access is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="Access or Role not found")

    return access_to_schema(access)


@router.put('/{access_id}/remove_roles', status_code=status.HTTP_200_OK, response_model=AccessSchema)
async def route_remove_roles_to_access(access_id: int = Path(..., ge=1),
                                       remove: AddRemoveRolesSchema = Body(...),
                                       credentials: CurrentCredentials = Depends(access)):
    """Dissociate roles to an access

    Args:
        access_id (int, optional): Access identifier. Defaults to Path(..., ge=1).
        remove (AddRemoveRolesSchema, optional): List of role IDs to remove. Defaults to Body(...).
        credentials (CurrentCredentials, optional): Depend bearer credentials. Defaults to Depends(access).

    Raises:
        HTTPException: HTTP_404_NOT_FOUND - Access or Role not found

    Returns:
        AccessSchema: Updated access
    """
    access: Access = remove_roles_to_access(access_id, remove.role_ids)
    if access is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="Access or Role not found")

    return access_to_schema(access)
