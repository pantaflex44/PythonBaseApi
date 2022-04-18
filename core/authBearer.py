#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

import asyncio
from datetime import datetime
import jwt
import time
import secrets
from typing import Any, Dict

from core import settings
from core.sql import get_db

from fastapi import Depends, Request, HTTPException, Response, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from sqlalchemy.orm import Session

from models.userModels import Role, User, Access
from models.methods.userMethods import get_higher_role_level, get_user
from schemas.authSchemas import CurrentCredentials

from schemas.userSchemas import UserProfile


def signJWT(id: int, username: str) -> Dict[str, str]:
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


def decodeJWT(token: str) -> dict:
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


def setTokenCookie(token: Dict[str, str], request: Request, response: Response):
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


def clearTokenCookie(request: Request, response: Response):
    """Destroy the token cookie

    Args:
        request (Request): Fastapi request
        response (Response): Fastapi response
    """
    response.delete_cookie(key=settings.jwt_cookie_name, secure=True, httponly=True, domain=request.client.host)


def createToken(id: int, username: str, request: Request, response: Response) -> Dict[str, str]:
    """Create a token payload

    Args:
        id (int): User identifier
        username (str): Username
        request (Request): Fastapi request
        response (Response): Fastapi response

    Returns:
        Dict[str, str]: The token payload
    """
    token: Dict[str, str] = signJWT(id, username)
    setTokenCookie(token, request, response)

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
            HTTPException: HTTP_403_FORBIDDEN - Invalid authentication scheme
            HTTPException: HTTP_403_FORBIDDEN - Invalid token or expired token
            HTTPException: HTTP_403_FORBIDDEN - Invalid token
            HTTPException: HTTP_403_FORBIDDEN - Invalid authorization code

        Returns:
            CurrentCredentials: Credential data. Current user, JWT token
        """
        credentials: HTTPAuthorizationCredentials = await super(Auth, self).__call__(request)
        if credentials:
            if not credentials.scheme == "Bearer":
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                    detail="Invalid authentication scheme.")

            bearer: dict = self.verify_jwt(credentials.credentials)
            if not bearer['isTokenValid'] or "csrf" not in bearer['payload']:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                    detail="Invalid token or expired token.")

            bearerCsrf: str = bearer['payload']['csrf']
            cookieCsrf: str = request.cookies.get(settings.jwt_cookie_name)
            if bearerCsrf != cookieCsrf:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                    detail="Invalid token.")

            return CurrentCredentials(current_user=self.payload_to_user(bearer['payload'], db),
                                      token=credentials.credentials)
        else:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                detail="Invalid authorization code.")

    def verify_jwt(self, jwtoken: str) -> dict:
        """Verify JWT token

        Args:
            jwtoken (str): The JWT token

        Returns:
            dict: Payload content
        """
        isTokenValid: bool = False

        try:
            payload: dict = decodeJWT(jwtoken)
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
            HTTPException: HTTP_401_UNAUTHORIZED - Unauthorized: invalid token
            HTTPException: HTTP_401_UNAUTHORIZED - Unauthorized: user not found
            HTTPException: HTTP_401_UNAUTHORIZED - Unauthorized: user account blocked or not activated

        Returns:
            UserProfile: User and user profile schemas
        """
        if "id" not in payload or "username" not in payload:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail="Unauthorized: invalid token.")

        user: UserProfile = get_user([User.id == payload['id'], User.username.like(payload['username'])])
        if user is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail="Unauthorized: user not found.")

        if not user.is_activated or user.is_blocked:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail="Unauthorized: user account blocked or not activated.")

        return user


async def access(request: Request, db: Session = Depends(get_db), credentials: CurrentCredentials = Depends(Auth())):
    """Access middleware.
    Used with route dependency injection.

    Args:
        request (Request): Fastapi request
        db (Session, optional): Database session. Defaults to Depends(get_db).
        credentials (CurrentCredentials, optional): Authentification controller instance. Defaults to Depends(Auth()).

    Raises:
        HTTPException: HTTP_500_INTERNAL_SERVER_ERROR - No access rights found for this route
        HTTPException: HTTP_401_UNAUTHORIZED - Unauthorized

    Returns:
        CurrentCredentials: Authentification controller instance
    """
    authorized = False

    routeName = request.scope['endpoint'].__name__
    if len(routeName) > 6 and routeName[:6].lower() == "route_":
        routeName = routeName[6:]

        access: Access = db.query(Access).filter(Access.route_name.like(routeName)).first()
        if access is None:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                                detail="No access rights found for this route.")

        allowed_levels = []
        for id in access.role_ids:
            role: Role = db.query(Role).filter(Role.id == id).first()
            if role is None:
                continue
            allowed_levels.append(role.role_level)
        allowed_levels = sorted(allowed_levels, reverse=True)

        higher_role_level: int = get_higher_role_level()
        for level in allowed_levels:
            if credentials.current_user.role_level == level or credentials.current_user.role_level == higher_role_level:
                authorized = True
                break

    if not authorized:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Unauthorized.")

    return credentials
