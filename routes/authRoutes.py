#!/usr/bin/env python3
# -*- encoding: utf-8 -*-


from core import settings
from core.authBearer import access, clearTokenCookie, createToken
from core.functions import sha512_compare
from core.sql import get_db

from fastapi import Body, Depends, status, APIRouter, HTTPException, Response, Request
from fastapi.responses import JSONResponse

from sqlalchemy.orm import Session

from models.authModels import User
from models.methods.authMethods import get_user_ex

from schemas.authSchemas import CurrentCredentials, TokenSchema, LoginSchema, UpdateTokenSchema
from schemas.authSchemas import UserProfile, UserProfileEx


router: APIRouter = APIRouter(prefix="/auth", tags=["auth"])


@router.post('/login', status_code=status.HTTP_200_OK, response_model=TokenSchema)
async def route_login(request: Request, response: Response,
                      login: LoginSchema = Body(...)):
    """Application login

    Args:
        request (Request): Fastapi request
        response (Response): Fastapi response
        login (LoginSchema, optional): Login informations. Defaults to Body(...).

    Raises:
        HTTPException: HTTP_404_NOT_FOUND - User not found
        HTTPException: HTTP_401_UNAUTHORIZED - Unauthorized: user account blocked or not activated

    Returns:
        TokenSchema: Bearer security. Access Token to use for bearer credentials.
    """
    userEx: UserProfileEx = get_user_ex([User.username.like(login.username.strip())])
    if userEx is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="User not found.")

    if not sha512_compare(login.password.strip(), userEx.hashed_password) \
            or not userEx.is_activated or userEx.is_blocked:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Unauthorized: user account blocked or not activated.")

    return createToken(userEx.id, userEx.username, request, response)


@router.post('/logout')
async def route_logout(request: Request, response: Response):
    """Logout

    Args:
        request (Request): Fastapi request
        response (Response): Fastapi response

    Returns:
        JSONResponse: Empty JSON response
    """
    clearTokenCookie(request, response)
    return JSONResponse({}, status_code=status.HTTP_200_OK)


@router.post('/update_token', status_code=status.HTTP_200_OK, response_model=TokenSchema)
async def route_update_token(request: Request, response: Response,
                             update: UpdateTokenSchema = Body(...),
                             credentials: CurrentCredentials = Depends(access)):
    """Update access Token while not expired

    Args:
        request (Request): Fastapi request
        response (Response): Fastapi response
        update (UpdateTokenSchema, optional): Data needed to update token. Defaults to Body(...).
        credentials (CurrentCredentials, optional): Depend bearer credentials. Defaults to Depends(access).

    Raises:
        HTTPException: HTTP_401_UNAUTHORIZED - Unauthorized

    Returns:
        TokenSchema: Bearer security. Access Token to use for bearer credentials.
    """
    if credentials.current_user.username != update.username or credentials.token != update.current_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Unauthorized.")

    return createToken(credentials.current_user.id, credentials.current_user.username, request, response)


@router.get('/me', status_code=status.HTTP_200_OK, response_model=UserProfile)
async def route_me(credentials: CurrentCredentials = Depends(access)):
    """Get the connected user account and profile

    Args:
        credentials (CurrentCredentials, optional): Depend bearer credentials. Defaults to Depends(access).

    Returns:
        UserProfile: User account and profile schemas
    """
    return credentials.current_user
