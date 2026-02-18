import uuid
from pathlib import Path

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials

from server.auth import _load_public_key, verify_token
from server.config import Settings

# Generate a test key pair at module level (fast, in-memory only)
_PRIVATE_KEY = ec.generate_private_key(ec.SECP256R1())
_PUBLIC_PEM = _PRIVATE_KEY.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)


def _sign(subject: str, jti: str, key: object) -> str:
    payload: dict[str, str] = {"sub": subject, "jti": jti}
    return pyjwt.encode(payload, key, algorithm="ES256")  # type: ignore[arg-type]


def _make_settings(tmp_path: object, public_pem: bytes, revoked_tokens_file: str) -> Settings:
    key_file = Path(str(tmp_path)) / "public.pem"
    key_file.write_bytes(public_pem)
    return Settings(
        vllm_base_url="http://127.0.0.1:9999",
        server_host="127.0.0.1",
        server_port=54912,
        max_audio_bytes=500 * 1024 * 1024,
        max_queue_size=5,
        jwt_public_key_file=str(key_file),
        revoked_tokens_file=revoked_tokens_file,
        require_https=False,
        vllm_model_name="vibevoice",
        vllm_temperature=0.0,
        vllm_top_p=1.0,
    )


def _reset_caches() -> None:
    """Clear both the public key LRU cache and the revocation cache."""
    import server.auth

    _load_public_key.cache_clear()
    server.auth._revocation_cache = (0.0, frozenset())


def test_valid_token(tmp_path: object) -> None:
    _reset_caches()
    revoked_file = Path(str(tmp_path)) / "revoked.txt"
    revoked_file.write_text("")
    settings = _make_settings(tmp_path, _PUBLIC_PEM, str(revoked_file))
    token = _sign("alice", uuid.uuid4().hex, _PRIVATE_KEY)
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)
    subject = verify_token(creds, settings)
    assert subject == "alice"


def test_invalid_token(tmp_path: object) -> None:
    _reset_caches()
    revoked_file = Path(str(tmp_path)) / "revoked.txt"
    revoked_file.write_text("")
    settings = _make_settings(tmp_path, _PUBLIC_PEM, str(revoked_file))
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials="not-a-jwt")
    with pytest.raises(HTTPException) as exc_info:
        verify_token(creds, settings)
    assert exc_info.value.status_code == 401


def test_no_public_key_configured(tmp_path: object) -> None:
    revoked_file = Path(str(tmp_path)) / "revoked.txt"
    revoked_file.write_text("")
    settings = Settings(
        vllm_base_url="http://127.0.0.1:9999",
        server_host="127.0.0.1",
        server_port=54912,
        max_audio_bytes=500 * 1024 * 1024,
        max_queue_size=5,
        jwt_public_key_file="",
        revoked_tokens_file=str(revoked_file),
        require_https=False,
        vllm_model_name="vibevoice",
        vllm_temperature=0.0,
        vllm_top_p=1.0,
    )
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials="any")
    with pytest.raises(HTTPException) as exc_info:
        verify_token(creds, settings)
    assert exc_info.value.status_code == 401


def test_wrong_signing_key(tmp_path: object) -> None:
    _reset_caches()
    revoked_file = Path(str(tmp_path)) / "revoked.txt"
    revoked_file.write_text("")
    settings = _make_settings(tmp_path, _PUBLIC_PEM, str(revoked_file))
    other_key = ec.generate_private_key(ec.SECP256R1())
    token = _sign("bob", uuid.uuid4().hex, other_key)
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)
    with pytest.raises(HTTPException) as exc_info:
        verify_token(creds, settings)
    assert exc_info.value.status_code == 401


def test_missing_sub_claim(tmp_path: object) -> None:
    _reset_caches()
    revoked_file = Path(str(tmp_path)) / "revoked.txt"
    revoked_file.write_text("")
    settings = _make_settings(tmp_path, _PUBLIC_PEM, str(revoked_file))
    token = pyjwt.encode({"jti": "abc"}, _PRIVATE_KEY, algorithm="ES256")
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)
    with pytest.raises(HTTPException) as exc_info:
        verify_token(creds, settings)
    assert exc_info.value.status_code == 401


def test_missing_jti_claim(tmp_path: object) -> None:
    _reset_caches()
    revoked_file = Path(str(tmp_path)) / "revoked.txt"
    revoked_file.write_text("")
    settings = _make_settings(tmp_path, _PUBLIC_PEM, str(revoked_file))
    token = pyjwt.encode({"sub": "alice"}, _PRIVATE_KEY, algorithm="ES256")
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)
    with pytest.raises(HTTPException) as exc_info:
        verify_token(creds, settings)
    assert exc_info.value.status_code == 401


def test_revoked_token(tmp_path: object) -> None:
    _reset_caches()
    jti = uuid.uuid4().hex
    revoked_file = Path(str(tmp_path)) / "revoked.txt"
    revoked_file.write_text(f"# Revoked tokens\n{jti}\n")

    settings = _make_settings(tmp_path, _PUBLIC_PEM, str(revoked_file))
    token = _sign("alice", jti, _PRIVATE_KEY)
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)
    with pytest.raises(HTTPException) as exc_info:
        verify_token(creds, settings)
    assert exc_info.value.status_code == 401
    assert "revoked" in exc_info.value.detail.lower()


def test_non_revoked_token_passes(tmp_path: object) -> None:
    _reset_caches()
    revoked_file = Path(str(tmp_path)) / "revoked.txt"
    revoked_file.write_text("some-other-jti\n")

    settings = _make_settings(tmp_path, _PUBLIC_PEM, str(revoked_file))
    token = _sign("alice", uuid.uuid4().hex, _PRIVATE_KEY)
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)
    subject = verify_token(creds, settings)
    assert subject == "alice"


def test_revocation_file_comments_ignored(tmp_path: object) -> None:
    _reset_caches()
    jti = uuid.uuid4().hex
    revoked_file = Path(str(tmp_path)) / "revoked.txt"
    revoked_file.write_text(f"# This is a comment\n\n# {jti}\n")

    settings = _make_settings(tmp_path, _PUBLIC_PEM, str(revoked_file))
    token = _sign("alice", jti, _PRIVATE_KEY)
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)
    # The jti appears only in a comment line, so it should NOT be revoked
    subject = verify_token(creds, settings)
    assert subject == "alice"
