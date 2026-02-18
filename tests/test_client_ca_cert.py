from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from client.client import VibevoiceClient


def test_default_verify() -> None:
    c = VibevoiceClient("http://localhost", "tok")
    assert c._verify is True


def test_verify_false() -> None:
    c = VibevoiceClient("http://localhost", "tok", verify=False)
    assert c._verify is False


def test_ca_cert_overrides_verify() -> None:
    c = VibevoiceClient("http://localhost", "tok", ca_cert="/tmp/ca.pem")
    assert c._verify == "/tmp/ca.pem"


def test_ca_cert_none_keeps_verify() -> None:
    c = VibevoiceClient("http://localhost", "tok", verify=False, ca_cert=None)
    assert c._verify is False


# ── CLI tests ────────────────────────────────────────────────────────


def test_cli_ca_cert_missing_file(tmp_path: Path) -> None:
    from client.cli import main

    fake_path = str(tmp_path / "nonexistent.pem")
    with (
        patch("sys.argv", ["vvv", "--server", "https://x", "--token", "t",
                           "--ca-cert", fake_path, "status"]),
        pytest.raises(SystemExit) as exc_info,
    ):
        main()
    assert exc_info.value.code == 1


def test_cli_ca_cert_valid_file(tmp_path: Path) -> None:
    """When --ca-cert points to a real file, the client should receive it."""
    ca = tmp_path / "ca.pem"
    ca.write_text("fake")

    captured_clients: list[VibevoiceClient] = []
    original_init = VibevoiceClient.__init__

    def spy_init(self: VibevoiceClient, *args: object, **kwargs: object) -> None:
        original_init(self, *args, **kwargs)  # type: ignore[arg-type]
        captured_clients.append(self)

    with (
        patch("sys.argv", ["vvv", "--server", "https://x", "--token", "t",
                           "--ca-cert", str(ca), "status"]),
        patch.object(VibevoiceClient, "__init__", spy_init),
        patch("client.cli.asyncio.run", side_effect=SystemExit(0)),
        pytest.raises(SystemExit),
    ):
        from client.cli import main
        main()

    assert len(captured_clients) == 1
    assert captured_clients[0]._verify == str(ca)
