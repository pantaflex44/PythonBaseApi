#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

import enum
from typing import Dict


debug: bool = True

app_title: str = "PythonBaseApi"
app_description: str = "Base Python API Model"
app_version: str = "0.1.0"
app_license: Dict[str, str] = {"name": "MIT License", "url": "https://opensource.org/licenses/MIT"}
app_contact: Dict[str, str] = {"name": "Christophe LEMOINE",  "url": "", "email": "pantaflex@tuta.io"}
app_terms: str = ""

api_scheme: str = "https"
api_host: str = "127.0.0.1"
api_port: int = 8443

allowed_hosts: list[str] = ["localhost", api_host]
cors_origins: list[str] = [f"{api_scheme}://{host}:{api_port}" for host in allowed_hosts]
cors_credentials: bool = True
cors_methods: list[str] = ["*"]
cors_headers: list[str] = ["Authorization", "Access-Control-Allow-Origin"]
cors_max_age: int = 600
default_rate_limiter: str = "1000/minute"
use_gzip: bool = True

jwt_algorithm: str = "HS256"
jwt_secret: str = "deff1952d59f883ece260e8683fed21ab0ad9a53323eca4f"
jwt_expires: int = 3600
jwt_cookie_name: str = "PBA_Token"

sql_scheme: str = "mysql+pymysql"
sql_database_name: str = "PythonBaseApi"
sql_username: str = "app"
sql_password: str = "Root1234!"
sql_host: str = "127.0.0.1"
sql_port: int = 3306
sql_connection_string: str = f"{sql_scheme}://{sql_username}:{sql_password}@{sql_host}:{sql_port}/{sql_database_name}?charset=utf8"


default_avatar_url = "http://placeimg.com/64/64/any"
default_roles = {"Administrator": 90, "Moderator": 80, "Editor": 70, "Redactor": 60, "User": 1}


# WARNING before change these settings
_argvs: Dict[str, str] = {"--db-install": "--db-install"}
