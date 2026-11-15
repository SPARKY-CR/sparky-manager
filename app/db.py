"""Database engine / session handling (SQLAlchemy 2.0, sync, SQLite WAL).

One file (``/opt/sparky-manager/data/panel.db`` by default), zero DB server.
WAL mode so reads don't block the traffic syncer's writes. Sync engine
on purpose: FastAPI runs sync endpoints in a threadpool and the DB is
small and local, so async adds complexity for no gain (DESIGN.md §3).
"""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from app import config as _config
from app.models import Base

# Engine/sessionmaker bound to the configured DB path. ``check_same_thread``
# is off because FastAPI serves sync endpoints from a threadpool.
_engine: Engine | None = None
SessionLocal: sessionmaker[Session] = sessionmaker(
    autoflush=False, autocommit=False, expire_on_commit=False
)


def _set_wal(dbapi_connection, _connection_record) -> None:
    """Enable WAL + foreign keys on every new SQLite connection."""
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


def get_engine(db_path: Path | str | None = None) -> Engine:
    """Return the (singleton) engine, creating it on first use.

    Pass ``db_path`` to point at a different SQLite file (tests); the
    default comes from :mod:`app.config`.
    """
    global _engine
    if _engine is not None and db_path is None:
        return _engine
    path = Path(db_path) if db_path is not None else _config.DB_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    engine = create_engine(
        f"sqlite:///{path}",
        connect_args={"check_same_thread": False},
        future=True,
    )
    event.listen(engine, "connect", _set_wal)
    if db_path is None:
        _engine = engine
        SessionLocal.configure(bind=engine)
    return engine


def init_db(engine: Engine | None = None) -> None:
    """Create all tables (no-op when they already exist)."""
    # Import models so every table is registered on Base.metadata.
    import app.models  # noqa: F401  (imported for its side effect)

    engine = engine or get_engine()
    Base.metadata.create_all(bind=engine)
    SessionLocal.configure(bind=engine)


def dispose_engine() -> None:
    """Dispose the current engine (and the singleton) without rebinding.

    Used by a restore before the DB file is swapped: pooled
    connections must be closed before the file is replaced, and the
    rebind happens afterwards via :func:`reset_engine`. The caller
    must have closed its sessions first.
    """
    global _engine
    bind = SessionLocal.kw.get("bind")
    for engine in {e for e in (bind, _engine) if e is not None}:
        engine.dispose()
    _engine = None


def reset_engine(db_path: Path | str | None = None) -> Engine:
    """Dispose the current engine and rebind to a fresh one.

    Used after a restore swaps the DB file on disk: the old engine's
    pooled connections point at the replaced file and must be closed
    before the new file is opened. ``db_path`` defaults to the path
    of the engine ``SessionLocal`` is currently bound to (the
    configured ``DB_PATH`` when nothing is bound yet). The caller must
    have closed its sessions first. Returns the new engine.
    """
    global _engine
    bind = SessionLocal.kw.get("bind")
    if db_path is None and bind is not None:
        try:
            db_path = bind.url.database
        except (AttributeError, ValueError):
            db_path = None
    dispose_engine()
    engine = get_engine(db_path)
    SessionLocal.configure(bind=engine)
    _engine = engine
    return engine


@contextmanager
def get_session() -> Iterator[Session]:
    """Yield a session; commit on success, roll back on error, always close.

    Usage::

        with get_session() as db:
            db.add(User(name="ali"))
    """
    if _engine is None:
        get_engine()
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


__all__ = [
    "get_engine",
    "init_db",
    "dispose_engine",
    "reset_engine",
    "get_session",
    "SessionLocal",
    "Base",
]
