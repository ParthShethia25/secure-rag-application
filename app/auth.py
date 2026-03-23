"""Authentication and role entitlements.

Trust boundary #1: this is where the caller's role is decided. The role
determines which documents are *candidates* for retrieval — it is passed down
into the vector search, not applied afterwards. Filtering after retrieval is the
classic RAG mistake: the restricted content has already been read, and usually
already been placed in the prompt, by the time you filter it.
"""
from __future__ import annotations

from dataclasses import dataclass

# Role -> the document audiences that role may read.
ROLE_ENTITLEMENTS: dict[str, tuple[str, ...]] = {
    "employee": ("employee",),
    "hr": ("employee", "hr"),
}


@dataclass(frozen=True)
class User:
    username: str
    role: str

    @property
    def allowed_roles(self) -> tuple[str, ...]:
        if self.role not in ROLE_ENTITLEMENTS:
            raise PermissionError(f"unknown role: {self.role}")
        return ROLE_ENTITLEMENTS[self.role]


# Two demo identities with different entitlements.
USERS = {
    "dana": User("dana", "employee"),   # general employee
    "harriet": User("harriet", "hr"),   # HR user
}


def authenticate(username: str) -> User:
    try:
        return USERS[username]
    except KeyError:
        raise PermissionError(f"unknown user: {username}") from None
