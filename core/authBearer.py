#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

import jwt
import time
import secrets
from datetime import datetime
from typing import Any, Dict

from core import settings
from core.sql import get_db

from fastapi import Depends, Path, Request, HTTPException, Response, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from sqlalchemy.orm import Session

from models.authModels import User
from models.methods.authMethods import get_user, is_allowed_level

from schemas.authSchemas import CurrentCredentials, UserProfile


def sign_JWT(id: int, username: str) -> Dict[str, str]:
    """Sign JWT token with user ID and username

    Args:
        id (int): User identifier
        username (str): Username

    Returns:
        Dict[str, str]: Dictionnary contains access token, csrf token, and expire timestamp
    """
    csrf: str = secrets.token_hex(10)
    expires: int = int(time.time() + settings.jwt_expires)
    payload: dict = {"id": id, "username": username, "expires": expires, "csrf": csrf}
    token: str = jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)

    return {"access_token": token, "csrf": csrf, "expires": expires}


def encode_JWT(user_id: int, data: str, expires: int) -> str:
    """Create and encode a JWT token

    Args:
        data (str): Data to encode
        expires (datetime): Expires datetime

    Returns:
        str: JWT token
    """
    payload: dict = {"user_id": user_id, "data": data, "expires": expires}
    token: str = jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)
    return token


def decode_JWT(token: str) -> dict:
    """Decode JWT token

    Args:
        token (str): The JWT token

    Returns:
        dict: Content dictionnary of decoded token
    """
    try:
        decoded_token: Dict[str, Any] = jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
        return decoded_token if decoded_token["expires"] >= time.time() else None
    except:
        return None


def set_token_cookie(token: Dict[str, str], request: Request, response: Response):
    """Set the token cookie include associated CSRF token

    Args:
        token (Dict[str, str]): JWT token with CSRF token and expire timestamp
        request (Request): Fastapi request
        response (Response): Fastapi response
    """
    csrf: str = token['csrf']
    expires: int = token['expires']

    expires_str: str = datetime.fromtimestamp(expires).strftime("%a, %d %b %Y %H:%M:%S GMT")
    response.set_cookie(key=settings.jwt_cookie_name, value=csrf, secure=True,
                        httponly=True, expires=expires_str, domain=request.client.host)


def clear_token_cookie(request: Request, response: Response):
    """Destroy the token cookie

    Args:
        request (Request): Fastapi request
        response (Response): Fastapi response
    """
    response.delete_cookie(key=settings.jwt_cookie_name, secure=True, httponly=True, domain=request.client.host)


def create_token(id: int, username: str, request: Request, response: Response) -> Dict[str, str]:
    """Create a token payload

    Args:
        id (int): User identifier
        username (str): Username
        request (Request): Fastapi request
        response (Response): Fastapi response

    Returns:
        Dict[str, str]: The token payload
    """
    token: Dict[str, str] = sign_JWT(id, username)
    set_token_cookie(token, request, response)

    del token['csrf']
    return token


class Auth(HTTPBearer):
    """Authentification controller

    Extends:
        HTTPBearer: Bearer security middleware
    """

    def __init__(self, auto_error: bool = True):
        """Contructor

        Args:
            auto_error (bool, optional): Auto generate error. Defaults to True.
        """
        super(Auth, self).__init__(auto_error=auto_error)

    async def __call__(self, request: Request, db: Session = Depends(get_db)):
        """Class caller interceptor

        Args:
            request (Request): Fastapi request
            db (Session, optional): Database session. Defaults to Depends(get_db).

        Raises:
            HTTPException: HTTP_401_UNAUTHORIZED - Invalid authentication scheme
            HTTPException: HTTP_401_UNAUTHORIZED - Invalid token or expired token
            HTTPException: HTTP_401_UNAUTHORIZED - Invalid token
            HTTPException: HTTP_401_UNAUTHORIZED - Invalid authorization code

        Returns:
            CurrentCredentials: Credential data. Current user, JWT token
        """
        credentials: HTTPAuthorizationCredentials = await super(Auth, self).__call__(request)
        if credentials:
            if not credentials.scheme == "Bearer":
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                    detail="Invalid authentication scheme.")

            bearer: dict = self.verify_JWT(credentials.credentials)
            if not bearer['isTokenValid'] or "csrf" not in bearer['payload']:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                    detail="Invalid token or expired token.")

            bearerCsrf: str = bearer['payload']['csrf']
            cookieCsrf: str = request.cookies.get(settings.jwt_cookie_name)
            if bearerCsrf != cookieCsrf:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                    detail="Invalid token origin.")

            return CurrentCredentials(current_user=self.payload_to_user(bearer['payload'], db),
                                      token=credentials.credentials)
        else:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail="Invalid authorization credentials.")

    def verify_JWT(self, jwtoken: str) -> dict:
        """Verify JWT token

        Args:
            jwtoken (str): The JWT token

        Returns:
            dict: Payload content
        """
        isTokenValid: bool = False

        try:
            payload: dict = decode_JWT(jwtoken)
        except:
            payload = None

        if payload:
            isTokenValid = True

        return {"isTokenValid": isTokenValid, "payload": payload}

    def payload_to_user(self, payload: dict, db: Session) -> UserProfile:
        """Transform payload content to user object

        Args:
            payload (dict): Payload content
            db (Session): Database session

        Raises:
            HTTPException: HTTP_401_UNAUTHORIZED - Malformed payload.
            HTTPException: HTTP_404_NOT_FOUND - User not found.
            HTTPException: HTTP_403_FORBIDDEN - User account not activated.
            HTTPException: HTTP_403_FORBIDDEN - User account blocked.

        Returns:
            UserProfile: User and user profile schemas
        """
        if "id" not in payload or "username" not in payload:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail="Malformed payload.")

        user: UserProfile = get_user([User.id == payload['id'], User.username.like(payload['username'])])
        if user is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                                detail="User not found.")

        if not user.is_activated:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                detail="User account not activated.")

        if user.is_blocked:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                detail="User account blocked.")

        return user


async def role_access(request: Request, credentials: CurrentCredentials = Depends(Auth())):
    """Access middleware.
    Current user role is allowed or not.
    Used with route dependency injection.

    Args:
        request (Request): Fastapi request
        credentials (CurrentCredentials, optional): Authentification controller instance. Defaults to Depends(Auth()).

    Raises:
        HTTPException: HTTP_403_FORBIDDEN - Unauthorized: user role not allowed.

    Returns:
        CurrentCredentials: Authentification controller instance
    """
    allowed: bool = is_allowed_level(route_name=request.scope['endpoint'].__name__,
                                     wanted_level=credentials.current_user.role_level)

    if not allowed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="User role not allowed.")

    return credentials


async def user_or_role_access(request: Request, user_id: int = Path(0), credentials: CurrentCredentials = Depends(Auth())):
    """Access middleware.
    Current user id or user role are allowed or not.
    Used with route dependency injection.

    Args:
        request (Request): Fastapi request
        user_id (int, optional): User ID found in route path. Defaults to Path(0).
        credentials (CurrentCredentials, optional): Authentification controller instance. Defaults to Depends(Auth()).

    Returns:
        CurrentCredentials: Authentification controller instance
    """
    if user_id == credentials.current_user.id:
        return credentials

    return await role_access(request, credentials)


async def user_access(request: Request, user_id: int = Path(0), credentials: CurrentCredentials = Depends(Auth())):
    """Access middleware.
    Current user id are allowed or not.
    Used with route dependency injection.

    Args:
        request (Request): Fastapi request
        user_id (int, optional): User ID found in route path. Defaults to Path(0).
        credentials (CurrentCredentials, optional): Authentification controller instance. Defaults to Depends(Auth()).

    Raises:
        HTTPException: HTTP_403_FORBIDDEN - Unauthorized: user account not allowed.

    Returns:
        CurrentCredentials: Authentification controller instance
    """
    if user_id != credentials.current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="User account not allowed.")

    return credentials
