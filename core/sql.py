#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

from contextvars import ContextVar
import sys

from fastapi import FastAPI

from core import settings
from core.functions import import_all_modules_from_dir, print_info, print_warning

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy_utils import database_exists, create_database


engine = create_engine(settings.sql_connection_string, connect_args={})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    """Get the database session (injection dependency).
    Rollback on exceptions.
    Autoclose after use.

    Yields:
        sessionmaker: Database session generator
    """
    db: sessionmaker = SessionLocal()
    try:
        yield db
    except Exception as ex:
        print_warning(ex)
        db.rollback()
    finally:
        db.close()


# Global database session
db_session: ContextVar[sessionmaker] = ContextVar('db_session', default=next(get_db()))


def install_db(app: FastAPI):
    """Database installation script

    Args:
        app (FastAPI): The application instance
    """
    print("")
    print_info(f"SQL database installation wanted...")
    print("")

    if not database_exists(engine.url):
        create_database(engine.url)
        print_info(f"- New SQL database '{settings.sql_database_name}', created")

    models: dict = import_all_modules_from_dir("models")
    for modelName, model in models.items():
        if "Base" in dir(model):
            model.Base.metadata.create_all(bind=engine)
            print_info(f"- All SQL tables in '{modelName}', created")
            print("")

            if "up" in dir(model):
                model.up(SessionLocal(), app)
                print_info(f"First installation executed with success")
            else:
                print_info(f"No first installation wanted")

    del models, modelName, model
