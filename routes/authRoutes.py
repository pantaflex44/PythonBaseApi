#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

import base64
from datetime import datetime, timedelta
from time import time
from core import settings
from core.authBearer import encode_JWT, role_access, clear_token_cookie, create_token, sign_JWT
from core.functions import generate_key, sha512_compare

from fastapi import Body, Depends, status, APIRouter, HTTPException, Response, Request
from fastapi.responses import JSONResponse

from models.authModels import User
from models.methods.authMethods import clean_expired_reset_tokens, get_user, get_user_ex, store_reset_token

from schemas.authSchemas import CurrentCredentials, PasswordResetSchema, PasswordResetTokenSchema, TokenSchema, LoginSchema, UpdateTokenSchema
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

    return create_token(userEx.id, userEx.username, request, response)


@router.post('/logout')
async def route_logout(request: Request, response: Response):
    """Logout

    Args:
        request (Request): Fastapi request
        response (Response): Fastapi response

    Returns:
        JSONResponse: Empty JSON response
    """
    clear_token_cookie(request, response)
    return JSONResponse({}, status_code=status.HTTP_200_OK)


@router.post('/update_token', status_code=status.HTTP_200_OK, response_model=TokenSchema)
async def route_update_token(request: Request, response: Response,
                             update: UpdateTokenSchema = Body(...),
                             credentials: CurrentCredentials = Depends(role_access)):
    """Update access Token while not expired

    Args:
        request (Request): Fastapi request
        response (Response): Fastapi response
        update (UpdateTokenSchema, optional): Data needed to update token. Defaults to Body(...).
        credentials (CurrentCredentials, optional): Depend bearer credentials. Defaults to Depends(role_access).

    Raises:
        HTTPException: HTTP_401_UNAUTHORIZED - Unauthorized

    Returns:
        TokenSchema: Bearer security. Access Token to use for bearer credentials.
    """
    if credentials.current_user.username != update.username or credentials.token != update.current_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Unauthorized.")

    return create_token(credentials.current_user.id, credentials.current_user.username, request, response)


@router.get('/me', status_code=status.HTTP_200_OK, response_model=UserProfile)
async def route_me(credentials: CurrentCredentials = Depends(role_access)):
    """Get the connected user account and profile

    Args:
        credentials (CurrentCredentials, optional): Depend bearer credentials. Defaults to Depends(role_access).

    Returns:
        UserProfile: User account and profile schemas
    """
    return credentials.current_user


@router.post('/reset_password', status_code=status.HTTP_200_OK, response_model=PasswordResetTokenSchema)
async def route_password_reset(request: Request, response: Response,
                               password_reset: PasswordResetSchema = Body(...)):
    """Create new reset password token

    Args:
        request (Request): Fastapi request
        response (Response): Fastapi response
        password_reset (PasswordResetSchema, optional): Password reset data. Defaults to Body(...).

    Raises:
        HTTPException: HTTP_404_NOT_FOUND - User not found
        HTTPException: HTTP_500_INTERNAL_SERVER_ERROR - Unable to store new reset token

    Returns:
        PasswordResetTokenSchema: All password reset needed informations
    """
    clean_expired_reset_tokens()

    user: UserProfile = get_user([User.username.like(password_reset.username.strip())])
    if user is None or user.email != password_reset.email.strip():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="User not found.")

    expires: int = int(time() + settings.reset_tokens_expires)
    reset_key: str = generate_key()
    if not store_reset_token(user.id, reset_key, expires):
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail="Unable to store new reset token.")

    jwt_token: str = encode_JWT(user.id, reset_key, expires)
    reset_token: str = base64.b64encode(jwt_token.encode('utf8')).decode('utf8')

    return PasswordResetTokenSchema(reset_token=reset_token,
                                    expires=expires)
