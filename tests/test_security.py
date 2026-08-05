from fastapi import Response
from pydantic import ValidationError
from sentinel.auth import Credentials, set_session_cookie
from sentinel.config import Settings
from sentinel.security import create_secret, hash_password, hash_secret, verify_password


def test_passwords_use_argon2_and_verify() -> None:
    encoded = hash_password("a-correct-long-password")
    assert encoded.startswith("$argon2id$")
    assert verify_password(encoded, "a-correct-long-password") is True
    assert verify_password(encoded, "incorrect-password") is False


def test_session_secrets_are_random_and_hashed() -> None:
    first, second = create_secret(), create_secret()
    assert first != second
    assert hash_secret(first) != first
    assert len(hash_secret(first)) == 64


def test_credentials_normalize_username_and_reject_short_password() -> None:
    credentials = Credentials(username="Home.Admin", password="a-long-password")  # noqa: S106
    assert credentials.username == "home.admin"
    try:
        Credentials(username="admin", password="short")  # noqa: S106
    except ValidationError:
        pass
    else:
        raise AssertionError("short password was accepted")


def test_session_cookie_security_attributes() -> None:
    response = Response()
    settings = Settings(sentinel_environment="test", cookie_secure=True)
    set_session_cookie(response, "secret-token", settings)
    cookie = response.headers["set-cookie"]
    assert "HttpOnly" in cookie
    assert "SameSite=strict" in cookie
    assert "Secure" in cookie
