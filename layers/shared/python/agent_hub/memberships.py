from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from agent_hub.rds_data import RdsData


ALLOWED_ROLES: set[str] = {"owner", "admin", "member", "guest", "blocked"}
ROLE_RANK: dict[str, int] = {
    # blocked means "no access" even if the numeric rank is low.
    "blocked": 0,
    "guest": 1,
    "member": 2,
    "admin": 3,
    "owner": 4,
}


def normalize_role(role: str) -> str:
    r = str(role or "").strip().lower()
    if r not in ALLOWED_ROLES:
        raise ValueError(f"invalid role: {role}")
    return r


def _role_satisfies(*, have: str, required: str) -> bool:
    have_n = normalize_role(have)
    req_n = normalize_role(required)
    if have_n == "blocked":
        return False
    return ROLE_RANK[have_n] >= ROLE_RANK[req_n]


@dataclass(frozen=True)
class AgentMembership:
    """A user's membership in an agent, joined with minimal agent metadata."""

    agent_id: str
    name: str
    role: str
    relationship_label: str | None
    disabled: bool


@dataclass(frozen=True)
class AgentMember:
    """A member row joined with user identity."""

    user_id: str
    cognito_sub: str
    email: str | None
    role: str
    relationship_label: str | None
    revoked_at: str | None


def list_agents_for_user(db: RdsData, *, user_id: str) -> list[AgentMembership]:
    rows = db.query(
        """
        SELECT a.agent_id::TEXT as agent_id,
               a.name as name,
               a.disabled as disabled,
               m.role as role,
               m.relationship_label as relationship_label
        FROM agent_memberships m
        JOIN agents a ON a.agent_id = m.agent_id
        WHERE m.user_id = :user_id::uuid
          AND m.revoked_at IS NULL
        ORDER BY a.created_at ASC
        """,
        {"user_id": user_id},
    )

    out: list[AgentMembership] = []
    for r in rows:
        out.append(
            AgentMembership(
                agent_id=str(r.get("agent_id") or ""),
                name=str(r.get("name") or ""),
                disabled=bool(r.get("disabled")),
                role=str(r.get("role") or ""),
                relationship_label=(
                    str(r.get("relationship_label")) if r.get("relationship_label") is not None else None
                ),
            )
        )
    return out


def get_membership(db: RdsData, *, agent_id: str, user_id: str) -> dict[str, Any] | None:
    rows = db.query(
        """
        SELECT role,
               relationship_label,
               revoked_at IS NULL as active
        FROM agent_memberships
        WHERE agent_id = :agent_id::uuid
          AND user_id = :user_id::uuid
        LIMIT 1
        """,
        {"agent_id": agent_id, "user_id": user_id},
    )
    if not rows:
        return None
    return rows[0]


def check_agent_permission(db: RdsData, *, agent_id: str, user_id: str, required_role: str) -> bool:
    required_role = normalize_role(required_role)
    mem = get_membership(db, agent_id=agent_id, user_id=user_id)
    if not mem:
        return False
    if not bool(mem.get("active")):
        return False
    have = str(mem.get("role") or "")
    return _role_satisfies(have=have, required=required_role)


def require_agent_permission(db: RdsData, *, agent_id: str, user_id: str, required_role: str) -> None:
    if not check_agent_permission(db, agent_id=agent_id, user_id=user_id, required_role=required_role):
        raise PermissionError("insufficient permissions")


def list_members_for_agent(db: RdsData, *, agent_id: str, include_revoked: bool = False) -> list[AgentMember]:
    where_rev = "" if include_revoked else "AND m.revoked_at IS NULL"
    rows = db.query(
        f"""
        SELECT u.user_id::TEXT as user_id,
               u.cognito_sub as cognito_sub,
               u.email as email,
               m.role as role,
               m.relationship_label as relationship_label,
               m.revoked_at::TEXT as revoked_at
        FROM agent_memberships m
        JOIN users u ON u.user_id = m.user_id
        WHERE m.agent_id = :agent_id::uuid
          {where_rev}
        ORDER BY m.created_at ASC
        """,
        {"agent_id": agent_id},
    )
    out: list[AgentMember] = []
    for r in rows:
        out.append(
            AgentMember(
                user_id=str(r.get("user_id") or ""),
                cognito_sub=str(r.get("cognito_sub") or ""),
                email=(str(r.get("email")).strip() if r.get("email") is not None else None),
                role=str(r.get("role") or ""),
                relationship_label=(
                    str(r.get("relationship_label")) if r.get("relationship_label") is not None else None
                ),
                revoked_at=(str(r.get("revoked_at")) if r.get("revoked_at") is not None else None),
            )
        )
    return out


def grant_membership(
    db: RdsData,
    *,
    agent_id: str,
    user_id: str,
    role: str,
    relationship_label: str | None,
    transaction_id: str | None = None,
) -> None:
    role_n = normalize_role(role)
    # Keep "owner" creation constrained to the dedicated flow.
    if role_n == "owner":
        raise ValueError("use claim_first_owner() to create the first owner")
    db.execute(
        """
        INSERT INTO agent_memberships (agent_id, user_id, role, relationship_label)
        VALUES (:agent_id::uuid, :user_id::uuid, :role, :relationship_label)
        ON CONFLICT (agent_id, user_id)
        DO UPDATE SET
          role = EXCLUDED.role,
          relationship_label = EXCLUDED.relationship_label,
          revoked_at = NULL
        """,
        {"agent_id": agent_id, "user_id": user_id, "role": role_n, "relationship_label": relationship_label},
        transaction_id=transaction_id,
    )


def update_membership(
    db: RdsData,
    *,
    agent_id: str,
    user_id: str,
    role: str,
    relationship_label: str | None,
    transaction_id: str | None = None,
) -> None:
    # For now, treat "update" as an upsert.
    grant_membership(
        db,
        agent_id=agent_id,
        user_id=user_id,
        role=role,
        relationship_label=relationship_label,
        transaction_id=transaction_id,
    )


def revoke_membership(db: RdsData, *, agent_id: str, user_id: str, transaction_id: str | None = None) -> None:
    db.execute(
        """
        UPDATE agent_memberships
        SET revoked_at = now()
        WHERE agent_id = :agent_id::uuid
          AND user_id = :user_id::uuid
          AND revoked_at IS NULL
        """,
        {"agent_id": agent_id, "user_id": user_id},
        transaction_id=transaction_id,
    )


def claim_first_owner(db: RdsData, *, agent_id: str, user_id: str, relationship_label: str | None = None) -> None:
    """Claim the first owner membership for an agent.

    This is intended for the CLI bootstrap flow: the first human user can
    explicitly claim ownership, but we do not auto-claim on login.
    """

    tx = db.begin()
    try:
        existing = db.query(
            """
            SELECT 1
            FROM agent_memberships
            WHERE agent_id = :agent_id::uuid
              AND role = 'owner'
              AND revoked_at IS NULL
            LIMIT 1
            """,
            {"agent_id": agent_id},
            transaction_id=tx,
        )
        if existing:
            raise PermissionError("owner already exists")

        # Upsert this user's membership to owner.
        db.execute(
            """
            INSERT INTO agent_memberships (agent_id, user_id, role, relationship_label)
            VALUES (:agent_id::uuid, :user_id::uuid, 'owner', :relationship_label)
            ON CONFLICT (agent_id, user_id)
            DO UPDATE SET
              role = EXCLUDED.role,
              relationship_label = EXCLUDED.relationship_label,
              revoked_at = NULL
            """,
            {"agent_id": agent_id, "user_id": user_id, "relationship_label": relationship_label},
            transaction_id=tx,
        )
        db.commit(tx)
    except Exception:
        try:
            db.rollback(tx)
        except Exception:
            pass
        raise

