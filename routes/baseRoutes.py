#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

from core import settings
from core.sql import get_db

from fastapi import Depends, status, APIRouter

from sqlalchemy.orm import Session

from schemas.baseSchemas import AboutSchema


router: APIRouter = APIRouter(prefix="", tags=["bases"])


@router.get('/about', status_code=status.HTTP_200_OK, response_model=AboutSchema)
async def route_about():
    return {"message": f"{settings.app_title} v{settings.app_version} - {settings.app_description}"}
