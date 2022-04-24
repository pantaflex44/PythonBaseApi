#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

from typing import Optional

from core import settings
from core.authBearer import role_access, user_or_role_access, clearTokenCookie

from fastapi import (
    Body,
    Depends,
    Path,
    Query,
    status,
    APIRouter,
    HTTPException,
    Request,
    Response
)

from models.methods.authMethods import (
    User,
    create_user,
    get_user,
    get_users,
    update_active_state,
    update_blocked_state,
    update_username,
    username_exists
)

from schemas.authSchemas import (
    CurrentCredentials,
    UpdateStateSchema,
    UpdateUsernameSchema,
    CreateSchema,
    UserProfile
)


router: APIRouter = APIRouter(prefix="/users", tags=["users"])


@router.get('/list', status_code=status.HTTP_200_OK, response_model=list[UserProfile])
async def route_get_all_users(offset: Optional[int] = Query(0, ge=0),
                              limit: Optional[int] = Query(100, ge=1),
                              credentials: CurrentCredentials = Depends(role_access)):
    """Get all users

    Args:
        offset (Optional[int], optional): Start index. Defaults to Query(0, ge=0).
        limit (Optional[int], optional): Quantity of returned rows. Defaults to Query(100, ge=1).
        credentials (CurrentCredentials, optional): Depend bearer credentials. Defaults to Depends(role_access).

    Returns:
        list[UserProfile]: List of User accounts and profiles
    """
    return get_users(offset=offset, limit=limit)


@router.get('/get/{user_id}', status_code=status.HTTP_200_OK, response_model=UserProfile)
async def route_get_unique_user(user_id: int = Path(..., ge=1),
                                credentials: CurrentCredentials = Depends(role_access)):
    """Get an user from his identifier

    Args:
        id (int, optional): User identifier. Defaults to Path(..., ge=1).
        credentials (CurrentCredentials, optional): Depend bearer credentials. Defaults to Depends(role_access).

    Raises:
        HTTPException: HTTP_404_NOT_FOUND - User not found

    Returns:
        UserProfile: User found account and profile
    """
    userFound: User = get_user([User.id == user_id])
    if userFound is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="User not found.")

    return userFound


@router.post('/create', status_code=status.HTTP_200_OK, response_model=UserProfile)
async def route_create_user(create: CreateSchema = Body(...),
                            credentials: CurrentCredentials = Depends(role_access)):
    """Create new user

    Args:
        create (CreateSchema, optional): User creation needed data. Defaults to Body(...).
        credentials (CurrentCredentials, optional): Depend bearer credentials. Defaults to Depends(role_access).

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


@router.put('/update/{user_id}/username', status_code=status.HTTP_200_OK, response_model=UserProfile)
async def route_update_username(request: Request, response: Response,
                                user_id: int = Path(..., ge=1),
                                update: UpdateUsernameSchema = Body(...),
                                credentials: CurrentCredentials = Depends(user_or_role_access)):
    """Update username

    Args:
        user_id (int, optional): The User ID. Defaults to Path(..., ge=1).
        update (UpdateUsernameSchema, optional): Update data. Defaults to Body(...).
        credentials (CurrentCredentials, optional): Depend bearer credentials. Defaults to Depends(user_or_role_access).

    Raises:
        HTTPException: HTTP_400_BAD_REQUEST - Username allready exists
        HTTPException: HTTP_500_INTERNAL_SERVER_ERROR - Unable to update this username

    Returns:
        UserProfile:  Updated User account and his profile
    """
    if username_exists(update.username):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail=f"Username '{update.username}' allready exists.")

    user: UserProfile = update_username(user_id, update.username)
    if user is None:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail=f"Unable to update this user.")

    if user_id == credentials.current_user.id:
        clearTokenCookie(request, response)

    return user


@router.put('/update/{user_id}/active_state', status_code=status.HTTP_200_OK, response_model=UserProfile)
async def route_update_active_state(user_id: int = Path(..., ge=1),
                                    update: UpdateStateSchema = Body(...),
                                    credentials: CurrentCredentials = Depends(role_access)):
    """Update active state

    Args:
        user_id (int, optional): The User ID. Defaults to Path(..., ge=1).
        update (UpdateStateSchema, optional): Update data. Defaults to Body(...).
        credentials (CurrentCredentials, optional): Depend bearer credentials. Defaults to Depends(role_access).

    Raises:
        HTTPException: HTTP_500_INTERNAL_SERVER_ERROR - Unable to update this user

    Returns:
        UserProfile:  Updated User account and his profile
    """
    user: UserProfile = update_active_state(user_id, update.state)
    if user is None:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail=f"Unable to update this user.")

    return user


@router.put('/update/{user_id}/blocked_state', status_code=status.HTTP_200_OK, response_model=UserProfile)
async def route_update_blocked_state(user_id: int = Path(..., ge=1),
                                     update: UpdateStateSchema = Body(...),
                                     credentials: CurrentCredentials = Depends(role_access)):
    """Update blocked state

    Args:
        user_id (int, optional): The User ID. Defaults to Path(..., ge=1).
        update (UpdateStateSchema, optional): Update data. Defaults to Body(...).
        credentials (CurrentCredentials, optional): Depend bearer credentials. Defaults to Depends(role_access).

    Raises:
        HTTPException: HTTP_500_INTERNAL_SERVER_ERROR - Unable to update this user

    Returns:
        UserProfile:  Updated User account and his profile
    """
    user: UserProfile = update_blocked_state(user_id, update.state)
    if user is None:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail=f"Unable to update this user.")

    return user
