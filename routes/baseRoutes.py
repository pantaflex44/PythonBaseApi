#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

from core import settings

from fastapi import (
    status,
    APIRouter
)

from fastapi_versioning import version

from schemas.baseSchemas import AboutSchema


router: APIRouter = APIRouter(prefix="", tags=["bases"])


@router.get('/about', status_code=status.HTTP_200_OK, response_model=AboutSchema)
@version(1)
async def route_about():
    return {"message": f"{settings.app_title} v{settings.app_version} - {settings.app_description}"}
