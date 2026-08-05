import hmac
import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Cookie, Depends, Header, HTTPException, Request, Response, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import delete, func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel.config import Settings, get_settings
from sentinel.database import get_session
from sentinel.models import AuditEvent, User
from sentinel.models import Session as LoginSession
from sentinel.security import (
    DUMMY_PASSWORD_HASH,
    create_secret,
    hash_password,
    hash_secret,
    verify_password,
)

router = APIRouter(prefix="/api/v1/auth", tags=["authentication"])
SESSION_COOKIE = "sentinel_session"


class Credentials(BaseModel):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[a-zA-Z0-9_.-]+$")
    password: str = Field(min_length=12, max_length=1024)

    @field_validator("username")
    @classmethod
    def normalize_username(cls, value: str) -> str:
        return value.lower()


class AuthenticatedUser(BaseModel):
    id: uuid.UUID
    username: str
    is_admin: bool


class AuthenticationResult(BaseModel):
    user: AuthenticatedUser
    csrf_token: str
    expires_at: datetime


class CsrfResult(BaseModel):
    csrf_token: str


def client_address(request: Request) -> str | None:
    return request.client.host if request.client else None


def set_session_cookie(response: Response, token: str, settings: Settings) -> None:
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=settings.session_hours * 3600,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="strict",
        path="/",
    )


async def issue_session(
    database: AsyncSession,
    user: User,
    request: Request,
    response: Response,
    settings: Settings,
    action: str,
) -> AuthenticationResult:
    token, csrf_token = create_secret(), create_secret()
    expires_at = datetime.now(UTC) + timedelta(hours=settings.session_hours)
    database.add(
        LoginSession(
            user_id=user.id,
            token_hash=hash_secret(token),
            csrf_hash=hash_secret(csrf_token),
            expires_at=expires_at,
        )
    )
    database.add(
        AuditEvent(
            actor_user_id=user.id,
            action=action,
            target_type="user",
            target_id=str(user.id),
            source_address=client_address(request),
        )
    )
    await database.commit()
    set_session_cookie(response, token, settings)
    return AuthenticationResult(
        user=AuthenticatedUser(id=user.id, username=user.username, is_admin=user.is_admin),
        csrf_token=csrf_token,
        expires_at=expires_at,
    )


async def authenticated_session(
    database: Annotated[AsyncSession, Depends(get_session)],
    session_token: Annotated[str | None, Cookie(alias=SESSION_COOKIE)] = None,
) -> tuple[User, LoginSession]:
    if not session_token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "authentication required")
    result = await database.execute(
        select(User, LoginSession)
        .join(LoginSession, LoginSession.user_id == User.id)
        .where(
            LoginSession.token_hash == hash_secret(session_token),
            LoginSession.expires_at > datetime.now(UTC),
            User.is_active.is_(True),
        )
    )
    authenticated = result.one_or_none()
    if authenticated is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "authentication required")
    return authenticated


async def csrf_protected_session(
    authenticated: Annotated[tuple[User, LoginSession], Depends(authenticated_session)],
    csrf_token: Annotated[str | None, Header(alias="X-CSRF-Token")] = None,
) -> tuple[User, LoginSession]:
    _, login_session = authenticated
    if not csrf_token or not hmac.compare_digest(login_session.csrf_hash, hash_secret(csrf_token)):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "invalid CSRF token")
    return authenticated


@router.post("/bootstrap", response_model=AuthenticationResult, status_code=201)
async def bootstrap_administrator(
    credentials: Credentials,
    request: Request,
    response: Response,
    database: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> AuthenticationResult:
    await database.execute(text("SELECT pg_advisory_xact_lock(731915823)"))
    administrator_count = await database.scalar(
        select(func.count()).select_from(User).where(User.is_admin.is_(True))
    )
    if administrator_count:
        await database.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, "administrator already initialized")
    user = User(
        username=credentials.username,
        password_hash=hash_password(credentials.password),
        is_admin=True,
    )
    database.add(user)
    await database.flush()
    return await issue_session(database, user, request, response, settings, "admin.bootstrap")


@router.post("/login", response_model=AuthenticationResult)
async def login(
    credentials: Credentials,
    request: Request,
    response: Response,
    database: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> AuthenticationResult:
    user = await database.scalar(select(User).where(User.username == credentials.username))
    candidate_hash = user.password_hash if user is not None else DUMMY_PASSWORD_HASH
    password_valid = verify_password(candidate_hash, credentials.password)
    valid = user is not None and user.is_active and password_valid
    if not valid:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid username or password")
    return await issue_session(database, user, request, response, settings, "auth.login")


@router.get("/me", response_model=AuthenticatedUser)
async def current_user(
    authenticated: Annotated[tuple[User, LoginSession], Depends(authenticated_session)],
) -> AuthenticatedUser:
    user, _ = authenticated
    return AuthenticatedUser(id=user.id, username=user.username, is_admin=user.is_admin)


@router.get("/csrf", response_model=CsrfResult)
async def refresh_csrf_token(
    database: Annotated[AsyncSession, Depends(get_session)],
    authenticated: Annotated[tuple[User, LoginSession], Depends(authenticated_session)],
) -> CsrfResult:
    _, login_session = authenticated
    csrf_token = create_secret()
    login_session.csrf_hash = hash_secret(csrf_token)
    await database.commit()
    return CsrfResult(csrf_token=csrf_token)


@router.post("/logout", status_code=204)
async def logout(
    response: Response,
    database: Annotated[AsyncSession, Depends(get_session)],
    authenticated: Annotated[tuple[User, LoginSession], Depends(csrf_protected_session)],
) -> None:
    user, login_session = authenticated
    await database.execute(delete(LoginSession).where(LoginSession.id == login_session.id))
    database.add(
        AuditEvent(
            actor_user_id=user.id,
            action="auth.logout",
            target_type="user",
            target_id=str(user.id),
        )
    )
    await database.commit()
    response.delete_cookie(SESSION_COOKIE, path="/")
