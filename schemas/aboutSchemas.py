#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

from typing import Optional
from pydantic import BaseModel, Field


class About(BaseModel):
    message: Optional[str] = Field(None, example="PythonBaseApi v0.1.0 - Base Python API Model")
