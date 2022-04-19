#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

from core import settings
from core.functions import verify_email, verify_password, verify_username


def validate_username_format(v: str) -> str:
    if v is None or not verify_username(v.strip()):
        raise ValueError(
            "Username must have min 8 chars, and can contains, lowercase, uppercase, digits, underscore, and point chars.")
    return v.strip()


def validate_passwords_format(v: str):
    if v is None or not verify_password(v.strip()):
        raise ValueError(
            "Password must have min 8 chars and 255 chars, 1 more lowercase, 1 more uppercase, 1 more digit, 1 more special chars are required.")
    return v.strip()


def validate_email_format(v: str) -> str:
    if v is None or (len(v.strip()) > 0 and not verify_email(v.strip())):
        raise ValueError("Invalid email address format.")
    return v.strip()


def validate_display_name_format(v: str):
    if v is None or len(v.strip()) == 0:
        return ""
    return v.strip()


def validate_avatar_format(v: str):
    if v is None or len(v.strip()) == 0:
        return settings.default_avatar_url
    return v.strip()


def validate_description_format(v: str):
    if v is None or len(v.strip()) == 0:
        return ""
    return v.strip()
