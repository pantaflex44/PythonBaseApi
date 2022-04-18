#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

import sys
from types import ModuleType
from typing import Dict

from core import settings
from core.functions import import_all_modules_from_dir, print_info, print_warning
from core.sql import install_db

import uvicorn

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.middleware.cors import CORSMiddleware

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.middleware import SlowAPIMiddleware
from slowapi.errors import RateLimitExceeded


print("")
print_warning(f"{settings.app_title} loading...")
print("")

app: FastAPI = FastAPI(Idebug=settings.debug,
                       title=settings.app_title,
                       description=settings.app_description,
                       version=settings.app_version,
                       license_info=settings.app_license,
                       terms_of_service=settings.app_terms)

print_info(f"- SQL engine initialized")

# mount statics directory
app.mount("/static", StaticFiles(directory="./statics"), name="static")
print_info(f"- Statics directory mounted")

# force HTTPS
app.add_middleware(HTTPSRedirectMiddleware)
print_info(f"- HTTPS redirection activated")

# block Headers injection
app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_hosts)
print_info(f"- Headers injections protection activated")

# CORS policies
app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origins, allow_credentials=settings.cors_credentials,
                   allow_methods=settings.cors_methods, allow_headers=settings.cors_headers,
                   max_age=settings.cors_max_age)
print_info(f"- CORS protection activated")

# api rate limiter
app.state.limiter = Limiter(key_func=get_remote_address, default_limits=[settings.default_rate_limiter])
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)
print_info(f"- Rate limiter activated: {settings.default_rate_limiter}")

# GZip compression
if settings.use_gzip:
    app.add_middleware(GZipMiddleware, minimum_size=500)
    print_info(f"- GZIP compression activated")

print_info("All modules loaded.")

# include all separate routes
print("")
modules: Dict[str, ModuleType] = import_all_modules_from_dir("routes")
for moduleName, module in modules.items():
    if "router" in dir(module):
        app.include_router(module.router)
        print_info(f"- routes '{moduleName}' loaded")
del modules, moduleName, module
print_info("All routes loaded.")
print("")

# database installation
if settings._argvs["--db-install"] in sys.argv:
    print_warning("New installation wanted...")
    install_db(app)


if __name__ == "__main__":
    if settings._argvs["--db-install"] in sys.argv:
        sys.exit(
            "\nAPI initialization ended with success.\nTo launch server, remove all installation flags.\n")

    # dev entry point : python -m api
    uvicorn.run("api:app",
                host=settings.api_host,
                port=settings.api_port,
                use_colors=True,
                log_level="debug" if settings.debug else "info",
                ssl_keyfile="./key.pem",
                ssl_certfile="./cert.pem",
                reload=True)
