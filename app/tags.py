"""Per-user tags (best-panel program, Phase B item 16).

Notes already exist on the user row; tags are the filterable half —
assign a short token to a user, filter the users list by it. No
panel reviewed documents per-user tags, so this is a small
differentiator for sparky.

Tags are single tokens (``TAG_RE``): Unicode word characters plus
``-`` and ``_``, 1–32 chars — Persian tags work (``\\w`` is Unicode
in Python). Spaces, commas and URL-significant characters are
rejected: tags travel in query strings (``/users?tag=...``) and in
the users-table filter, so they must stay one clean token.
"""

from __future__ import annotations

import re
from typing import Optional

from sqlalchemy.orm import Session as DbSession

from app.models import UserTag

#: One token: letters/digits/underscore (Unicode — Persian works)
#: plus hyphen. 1–32 chars.
TAG_RE = re.compile(r"^[\w-]{1,32}$", re.UNICODE)

MAX_TAGS_PER_USER = 20


def normalize_tag(raw: str) -> Optional[str]:
    """A cleaned tag, or ``None`` when the input is not a valid tag
    (empty, too long, or carrying a disallowed character). Tags are
    lowercased — "VIP" and "vip" are the same tag (otherwise the
    filter would treat near-identical tags as different ones).
    Persian tags have no case, so lowercasing is a no-op for them."""
    tag = (raw or "").strip().lower()
    if not tag or not TAG_RE.match(tag):
        return None
    return tag


def tags_for_user(db: DbSession, user_id: int) -> list[str]:
    """The user's tags, sorted (deterministic order for the UI)."""
    rows = (
        db.query(UserTag.tag)
        .filter(UserTag.user_id == user_id)
        .order_by(UserTag.tag)
        .all()
    )
    return [row[0] for row in rows]


def tags_by_user(db: DbSession) -> dict[int, list[str]]:
    """``{user_id: [tags]}`` in ONE query (users list rendering)."""
    out: dict[int, list[str]] = {}
    for row in db.query(UserTag).order_by(UserTag.tag).all():
        out.setdefault(row.user_id, []).append(row.tag)
    return out


def all_tags(db: DbSession) -> list[str]:
    """Every tag in use, sorted (the users-list filter options)."""
    rows = db.query(UserTag.tag).distinct().order_by(UserTag.tag).all()
    return [row[0] for row in rows]


def user_ids_with_tag(db: DbSession, tag: str) -> set[int]:
    """User ids carrying ``tag`` (the users-list filter)."""
    rows = db.query(UserTag.user_id).filter(UserTag.tag == tag).all()
    return {row[0] for row in rows}


def add_tag(db: DbSession, user_id: int, raw: str) -> Optional[str]:
    """Add ``raw`` as a tag on the user. Returns the stored tag, or
    ``None`` when the input is invalid or the user is at the tag
    cap. Adding a tag the user already has is a no-op that returns
    the tag (not an error — the web flow redirects without an error
    flash for it). Commits on success."""
    tag = normalize_tag(raw)
    if tag is None:
        return None
    existing = (
        db.query(UserTag)
        .filter(UserTag.user_id == user_id, UserTag.tag == tag)
        .first()
    )
    if existing is not None:
        return tag
    count = db.query(UserTag).filter(UserTag.user_id == user_id).count()
    if count >= MAX_TAGS_PER_USER:
        return None
    db.add(UserTag(user_id=user_id, tag=tag))
    db.commit()
    return tag


def remove_tag(db: DbSession, user_id: int, raw: str) -> bool:
    """Remove ``raw`` from the user. True when a tag was removed."""
    tag = normalize_tag(raw)
    if tag is None:
        return False
    row = (
        db.query(UserTag)
        .filter(UserTag.user_id == user_id, UserTag.tag == tag)
        .first()
    )
    if row is None:
        return False
    db.delete(row)
    db.commit()
    return True


def delete_tags_for_user(db: DbSession, user_id: int) -> int:
    """Delete all tags of a user (user deletion cleanup). Commits."""
    deleted = (
        db.query(UserTag)
        .filter(UserTag.user_id == user_id)
        .delete(synchronize_session=False)
    )
    db.commit()
    return int(deleted)


__all__ = [
    "TAG_RE",
    "MAX_TAGS_PER_USER",
    "normalize_tag",
    "tags_for_user",
    "tags_by_user",
    "all_tags",
    "user_ids_with_tag",
    "add_tag",
    "remove_tag",
    "delete_tags_for_user",
]
