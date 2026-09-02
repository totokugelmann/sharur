"""
Sharur SAIC - tests/conftest.py

Fixtures compartidos: base de datos SQLite en memoria para tests
rapidos (los tests de integracion/e2e contra Postgres real usan
DATABASE_URL del entorno de CI, ver .github/workflows/ci.yml).
"""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.models.base import Base


@pytest.fixture()
def db_session():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine)
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
