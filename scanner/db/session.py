from collections.abc import Generator
from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from scanner.db.models import Base

# Default database path: data/scanner.db in the workspace root
BASE_DIR = Path(__file__).resolve().parent.parent.parent
DATA_DIR = BASE_DIR / "data"
DEFAULT_DB_FILE = DATA_DIR / "scanner.db"
DEFAULT_DATABASE_URL = f"sqlite:///{DEFAULT_DB_FILE}"

_engine = None
_SessionLocal = None


def get_db_path() -> Path:
    """Return the database file path, ensuring parent directory exists."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    return DEFAULT_DB_FILE


def get_engine(db_url: str | None = None):
    """Get or create the SQLAlchemy engine."""
    global _engine, _SessionLocal
    if _engine is None or db_url is not None:
        if db_url is None:
            get_db_path()
            url = DEFAULT_DATABASE_URL
        else:
            url = db_url

        _engine = create_engine(
            url,
            connect_args={"check_same_thread": False} if "sqlite" in url else {},
        )
        _SessionLocal = sessionmaker(
            autocommit=False,
            autoflush=False,
            bind=_engine,
            expire_on_commit=False,
        )
    return _engine


def get_session_factory():
    """Get SessionLocal factory."""
    global _SessionLocal
    if _SessionLocal is None:
        get_engine()
    return _SessionLocal


def init_db(engine=None) -> None:
    """Create all database tables if they do not exist."""
    target_engine = engine or get_engine()
    Base.metadata.create_all(bind=target_engine)


def get_db() -> Generator[Session, None, None]:
    """Dependency that yields a database session and closes it afterwards."""
    SessionLocal = get_session_factory()
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def set_custom_engine(engine) -> None:
    """Set custom engine and session maker (primarily for testing)."""
    global _engine, _SessionLocal
    _engine = engine
    _SessionLocal = sessionmaker(
        autocommit=False,
        autoflush=False,
        bind=engine,
        expire_on_commit=False,
    )
    Base.metadata.create_all(bind=engine)
