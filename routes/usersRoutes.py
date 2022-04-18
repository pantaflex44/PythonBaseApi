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

from models.methods.userMethods import (
    User,
    create_user,
    get_user,
    get_users,
    username_exists
)

from schemas.authSchemas import CurrentCredentials
from schemas.userSchemas import (
    CreateSchema,
    UserProfile
)


router: APIRouter = APIRouter(prefix="/users", tags=["users"])


@router.get('/list', status_code=status.HTTP_200_OK, response_model=list[UserProfile])
async def route_get_all_users(offset: Optional[int] = Query(0, ge=0),
                              limit: Optional[int] = Query(100, ge=1),
                              credentials: CurrentCredentials = Depends(access)):
    """Get all users

    Args:
        offset (Optional[int], optional): Start index. Defaults to Query(0, ge=0).
        limit (Optional[int], optional): Quantity of returned rows. Defaults to Query(100, ge=1).
        credentials (CurrentCredentials, optional): Depend bearer credentials. Defaults to Depends(access).

    Returns:
        list[UserProfile]: List of User accounts and profiles
    """
    return get_users(offset, limit)


@router.get('/get/{id}', status_code=status.HTTP_200_OK, response_model=UserProfile)
async def route_get_unique_user(id: int = Path(..., ge=1),
                                credentials: CurrentCredentials = Depends(access)):
    """Get an user from his identifier

    Args:
        id (int, optional): User identifier. Defaults to Path(..., ge=1).
        credentials (CurrentCredentials, optional): Depend bearer credentials. Defaults to Depends(access).

    Raises:
        HTTPException: HTTP_404_NOT_FOUND - User not found

    Returns:
        UserProfile: User found account and profile
    """
    userFound: User = get_user([User.id == id])
    if userFound is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="User not found.")

    return userFound


@router.post('/create', status_code=status.HTTP_200_OK, response_model=UserProfile)
async def route_create_user(create: CreateSchema = Body(...),
                            credentials: CurrentCredentials = Depends(access)):
    """Create new user

    Args:
        create (CreateSchema, optional): User creation needed data. Defaults to Body(...).
        credentials (CurrentCredentials, optional): Depend bearer credentials. Defaults to Depends(access).

    Raises:
        HTTPException: HTTP_400_BAD_REQUEST - Username allready exists
        HTTPException: HTTP_500_INTERNAL_SERVER_ERROR - Unable to create this user

    Returns:
        UserProfile:  Created User account and initial default profile
    """
    if username_exists(create.username):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail=f"Username '{create.username}' allready exists.")

    user: UserProfile = create_user(create.username, create.password, create.role_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail=f"Unable to create this user.")

    return user
