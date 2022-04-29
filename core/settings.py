#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

from typing import Dict

# debug mode
debug: bool = True

# app informations
app_title: str = "PythonBaseApi"
app_description: str = "Project base to create web Rest API with Python over Fastify framework."
app_version: str = "0.1.0"
app_license: Dict[str, str] = {"name": "MIT License",
                               "url": "https://opensource.org/licenses/MIT"}
app_contact: Dict[str, str] = {"name": "Christophe LEMOINE",
                               "url": "https://github.com/pantaflex44/PythonBaseApi",
                               "email": "pantaflex@tuta.io"}
app_terms: str = ""

# api details for script mode (http details)
api_scheme: str = "https"
api_host: str = "127.0.0.1"  # server host
api_port: int = 8443  # server port

# security and system settings
allowed_hosts: list[str] = ["localhost", api_host]
cors_origins: list[str] = [f"{api_scheme}://{host}:{api_port}" for host in allowed_hosts]
cors_credentials: bool = True
cors_methods: list[str] = ["*"]
cors_headers: list[str] = ["Authorization", "Access-Control-Allow-Origin"]
cors_max_age: int = 600  # seconds
default_rate_limiter: int = 1000  # per minute
use_gzip: bool = True
reset_tokens_expires = 60 * 60 * 8  # seconds
auto_activate_user_account = False

# JWT settings
jwt_algorithm: str = "HS256"
jwt_secret: str = "deff1952d59f883ece260e8683fed21ab0ad9a53323eca4f"  # functions.py > generate_key()
jwt_expires: int = 3600  # seconds
jwt_cookie_name: str = "PBA_Token"

# SQL settings
sql_scheme: str = "mysql+pymysql"
sql_database_name: str = "PythonBaseApi"
sql_username: str = "root"
sql_password: str = "Admin1234!"
sql_host: str = "127.0.0.1"
sql_port: int = 3306
sql_connection_string: str = f"{sql_scheme}://{sql_username}:{sql_password}@{sql_host}:{sql_port}/{sql_database_name}?charset=utf8"

# defaults data
default_avatar_url = "http://placeimg.com/64/64/any"
default_roles = {"Administrator": 90, "Moderator": 80, "Editor": 70, "Redactor": 60, "User": 1}


# WARNING before change these settings
_argvs: Dict[str, str] = {"--db-install": "--db-install",
                          "--generate-jwt-secret": "--generate-jwt-secret"}
