#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

import hashlib
import os
import binascii
import glob
import re
from importlib import import_module
from types import ModuleType
from typing import AnyStr, Dict


def sha512_hash(password: str) -> str:
    """Hash string with SHA512

    Args:
        password (str): String to hash

    Returns:
        str: Hashed string
    """
    return hashlib.sha512(password.encode("utf8")).hexdigest()


def sha512_compare(password: str, hash: str) -> bool:
    """Compare two SHA512 hashes

    Args:
        password (str): String to compare
        hash (str): Original hashed string

    Returns:
        bool: True, string to hash equals hashed string, else, False
    """
    return (sha512_hash(password) == hash)


def generate_key() -> str:
    """Generate random key

    Returns:
        str: Random key generated
    """
    return binascii.hexlify(os.urandom(24)).decode("utf-8")


def import_all_modules_from_dir(dirname: str) -> Dict[str, ModuleType]:
    """List and import all modules found from base dir

    Args:
        dirname (str): Base dir to recurvely start research

    Returns:
        Dict[str, ModuleType]: List of imported module. { "moduleName": module }
    """
    modules: Dict[str, ModuleType] = dict()
    files: list[AnyStr@glob] = glob.glob(f"{dirname}/*.py")
    for f in files:
        if os.path.isfile(f) and not os.path.basename(f).startswith('_'):
            moduleName: str = os.path.basename(f)[:-3]
            if moduleName not in modules.keys():
                module: ModuleType = import_module(f".{moduleName}", dirname)
                modules[moduleName] = module
    return modules


def print_info(message: str):
    """Print info to console

    Args:
        message (str): Message to print
    """
    print(f"INFO:\t  {message}")


def print_warning(message: str):
    """Print warning to console

    Args:
        message (str): Message to print
    """
    print(f"WARNING:  {message}")


def verify_username(username: str) -> bool:
    """Verify username format.
    Min 8 to 255 characters, only lowercase, uppercase, digits, underscore and point chars.

    Args:
        username (str): Username

    Returns:
        bool: True, username correctly formatted, else, False
    """
    return re.match(r'^(?=[a-zA-Z0-9._]{8,255}$)(?!.*[_.]{2})[^_.].*[^_.]$', username) is not None


def verify_password(password: str) -> bool:
    """Verify password format.
    Min 8 to 255 characters, with one or more lowercase, uppercase, digits and specials chars.

    Args:
        password (str): Password to verify

    Returns:
        bool: True, password correct, else, False
    """
    return re.match(
        r'^.*(?=.{8,255})(?=.*[a-zA-Z])(?=.*?[A-Z])(?=.*\d)[a-zA-Z0-9!@£$%^&*()_+={}?:~\[\]]+$', password) is not None


def verify_email(email: str) -> bool:
    """Verify email format.

    Args:
        email (str): Email to verify

    Returns:
        bool: True, email correctly formatted, else, False
    """
    return re.fullmatch(
        r"([-!#-'*+/-9=?A-Z^-~]+(\.[-!#-'*+/-9=?A-Z^-~]+)*|\"([]!#-[^-~ \t]|(\\[\t -~]))+\")@([-!#-'*+/-9=?A-Z^-~]+(\.[-!#-'*+/-9=?A-Z^-~]+)*|\[[\t -Z^-~]*])",
        email) is not None


def verify_role_name(role_name: str) -> bool:
    """Verify role name format.
    Min 3 to 255 characters, only lowercase, uppercase, digits, underscore and point chars.

    Args:
        role_name (str): Role name

    Returns:
        bool: True, role name correctly formatted, else, False
    """
    return re.match(r'^(?=[a-zA-Z0-9._]{3,255}$)(?!.*[_.]{2})[^_.].*[^_.]$', role_name) is not None


def verify_role_level(role_level: int) -> bool:
    """Verify role level format.
    Min 1 to 99.

    Args:
        role_level (int): Role level

    Returns:
        bool: True, role lvel correctly formatted, else, False
    """
    return 99 >= role_level >= 1
