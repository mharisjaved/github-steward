"""Linux AF_UNIX protocol and peer-authorization tests."""

from __future__ import annotations

import os
import socket
import struct
import time
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from threading import Event, Thread
from typing import cast

import pytest

from github_steward.infrastructure.broker import unix_socket
from github_steward.infrastructure.broker.credential_broker import (
    BrokerFailureCode,
    CredentialBrokerError,
    MintReadTokenResult,
)
from github_steward.infrastructure.broker.unix_socket import (
    PROTOCOL_VERSION,
    UnixBrokerClient,
    UnixBrokerProtocolError,
    UnixBrokerServer,
)
from github_steward.ports.secrets import OpaqueBearerToken

_MISSING = object()


class FakeBroker:
    def __init__(self, token: str = "opaque") -> None:
        self.token = token
        self.calls: list[str] = []
        self.failure: CredentialBrokerError | None = None

    def MintReadToken(self, work_record_id: str) -> MintReadTokenResult:
        self.calls.append(work_record_id)
        if self.failure is not None:
            raise self.failure
        return MintReadTokenResult(
            OpaqueBearerToken(self.token),
            123456,
            7,
            datetime(2026, 8, 18, 13, 0, tzinfo=UTC),
        )


class ExplodingBroker(FakeBroker):
    def MintReadToken(self, work_record_id: str) -> MintReadTokenResult:
        raise RuntimeError("internal diagnostic must not cross the socket")


def _start(
    path: Path,
    broker: FakeBroker,
    *,
    allowed_uids: frozenset[int] | None = None,
    allowed_gids: frozenset[int] | None = None,
    maximum_frame_bytes: int = 65_536,
) -> tuple[Thread, list[BaseException]]:
    ready = Event()
    errors: list[BaseException] = []
    server = UnixBrokerServer(
        socket_path=path,
        broker=broker,
        allowed_uids=allowed_uids or frozenset({os.getuid()}),
        allowed_gids=allowed_gids or frozenset({os.getgid()}),
        maximum_frame_bytes=maximum_frame_bytes,
    )

    def serve() -> None:
        try:
            server.serve_once(ready=ready.set)
        except BaseException as exc:
            errors.append(exc)

    thread = Thread(target=serve)
    thread.start()
    assert ready.wait(2)
    assert server.socket_family == socket.AF_UNIX
    return thread, errors


def _finish(thread: Thread, errors: list[BaseException], path: Path) -> None:
    thread.join(2)
    assert not thread.is_alive()
    assert errors == []
    assert not path.exists()


@pytest.mark.parametrize("token", ["short", "x" * 500])
def test_authorized_peer_mints_opaque_token_over_one_bounded_frame(
    tmp_path: Path,
    token: str,
) -> None:
    path = tmp_path / "broker.sock"
    broker = FakeBroker(token)
    thread, errors = _start(path, broker)

    client = UnixBrokerClient(socket_path=path)
    result = client.MintReadToken("work-1")

    assert client.socket_family == socket.AF_UNIX
    assert result.token.matches(token)
    assert result.repository_id == 123456
    assert result.authorization_version == 7
    assert result.expires_at == datetime(2026, 8, 18, 13, 0, tzinfo=UTC)
    assert broker.calls == ["work-1"]
    _finish(thread, errors, path)


def test_success_response_uses_exact_canonical_utc_expiry_wire_value(
    tmp_path: Path,
) -> None:
    path = tmp_path / "broker.sock"
    broker = FakeBroker("opaque")
    thread, errors = _start(path, broker)

    response = _raw_exchange(path, b'{"version":1,"work_record_id":"work-1"}')

    assert response == {
        "version": 1,
        "token": "opaque",
        "repository_id": 123456,
        "authorization_version": 7,
        "expires_at": "2026-08-18T13:00:00Z",
    }
    assert broker.calls == ["work-1"]
    _finish(thread, errors, path)


def _raw_exchange(
    path: Path, payload: bytes, *, declared: int | None = None
) -> dict[str, object]:
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        connection.connect(str(path))
        length = len(payload) if declared is None else declared
        connection.sendall(struct.pack("!I", length) + payload)
        return unix_socket._receive_mapping(
            connection,
            maximum_frame_bytes=65_536,
        )
    finally:
        connection.close()


@pytest.mark.parametrize(
    ("payload", "declared", "error"),
    [
        (
            b'{"version":1,"work_record_id":"x","extra":1}',
            None,
            "UNKNOWN_OR_MISSING_FIELD",
        ),
        (b'{"version":1,"version":1,"work_record_id":"x"}', None, "MALFORMED_JSON"),
        (b'{"version":2,"work_record_id":"x"}', None, "UNSUPPORTED_VERSION"),
        (b'{"version":true,"work_record_id":"x"}', None, "UNSUPPORTED_VERSION"),
        (b'{"version":1,"work_record_id":""}', None, "INVALID_WORK_RECORD_ID"),
        (b"\xff", None, "MALFORMED_JSON"),
        (b"{}", 65_537, "FRAME_SIZE_REJECTED"),
    ],
)
def test_malformed_duplicate_unknown_and_oversized_requests_are_rejected(
    tmp_path: Path,
    payload: bytes,
    declared: int | None,
    error: str,
) -> None:
    path = tmp_path / "broker.sock"
    broker = FakeBroker()
    thread, errors = _start(path, broker)
    response = _raw_exchange(path, payload, declared=declared)
    assert response == {"version": PROTOCOL_VERSION, "error": error}
    assert broker.calls == []
    _finish(thread, errors, path)


def test_two_buffered_requests_are_rejected_as_multiple(tmp_path: Path) -> None:
    path = tmp_path / "broker.sock"
    broker = FakeBroker()
    thread, errors = _start(path, broker)
    raw = b'{"version":1,"work_record_id":"x"}'
    frame = struct.pack("!I", len(raw)) + raw
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        connection.connect(str(path))
        connection.sendall(frame + frame)
        response = unix_socket._receive_mapping(
            connection,
            maximum_frame_bytes=65_536,
        )
    finally:
        connection.close()
    assert response["error"] == "MULTIPLE_REQUESTS_REJECTED"
    assert broker.calls == []
    _finish(thread, errors, path)


@pytest.mark.parametrize(
    ("uids", "gids"),
    [
        (frozenset({os.getuid() + 1}), frozenset({os.getgid()})),
        (frozenset({os.getuid()}), frozenset({os.getgid() + 1})),
    ],
)
def test_uid_and_gid_are_both_required_pid_is_not_sufficient(
    tmp_path: Path,
    uids: frozenset[int],
    gids: frozenset[int],
) -> None:
    path = tmp_path / "broker.sock"
    broker = FakeBroker()
    thread, errors = _start(
        path,
        broker,
        allowed_uids=uids,
        allowed_gids=gids,
    )
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        connection.connect(str(path))
        response = unix_socket._receive_mapping(
            connection,
            maximum_frame_bytes=65_536,
        )
    finally:
        connection.close()
    assert response == {"version": 1, "error": "PEER_NOT_AUTHORIZED"}
    assert broker.calls == []
    _finish(thread, errors, path)


def test_broker_failures_return_only_safe_code(tmp_path: Path) -> None:
    path = tmp_path / "broker.sock"
    broker = FakeBroker()
    broker.failure = CredentialBrokerError(
        BrokerFailureCode.AUTHORIZATION_DENIED,
        "unsafe diagnostic detail",
    )
    thread, errors = _start(path, broker)
    with pytest.raises(UnixBrokerProtocolError) as raised:
        UnixBrokerClient(socket_path=path).MintReadToken("work-1")
    assert raised.value.code == BrokerFailureCode.AUTHORIZATION_DENIED.value
    assert "unsafe diagnostic detail" not in str(raised.value)
    _finish(thread, errors, path)


def test_existing_path_and_invalid_configuration_are_not_overwritten(
    tmp_path: Path,
) -> None:
    path = tmp_path / "broker.sock"
    path.write_text("owned by caller", encoding="utf-8")
    server = UnixBrokerServer(
        socket_path=path,
        broker=FakeBroker(),
        allowed_uids=frozenset({os.getuid()}),
        allowed_gids=frozenset({os.getgid()}),
    )
    with pytest.raises(RuntimeError):
        server.serve_once()
    assert path.read_text(encoding="utf-8") == "owned by caller"

    with pytest.raises(ValueError):
        UnixBrokerServer(
            socket_path=Path("relative.sock"),
            broker=FakeBroker(),
            allowed_uids=frozenset({os.getuid()}),
            allowed_gids=frozenset({os.getgid()}),
        )
    with pytest.raises(ValueError):
        UnixBrokerClient(socket_path=Path("relative.sock"))


@pytest.mark.parametrize(
    ("uids", "gids", "maximum_frame_bytes"),
    [
        (frozenset(), frozenset({0}), 1),
        (frozenset({0}), frozenset(), 1),
        (frozenset({-1}), frozenset({0}), 1),
        (frozenset({0}), frozenset({-1}), 1),
        (frozenset({0}), frozenset({0}), 0),
    ],
)
def test_server_rejects_invalid_peer_and_frame_configuration(
    tmp_path: Path,
    uids: frozenset[int],
    gids: frozenset[int],
    maximum_frame_bytes: int,
) -> None:
    with pytest.raises(ValueError):
        UnixBrokerServer(
            socket_path=tmp_path / "broker.sock",
            broker=FakeBroker(),
            allowed_uids=uids,
            allowed_gids=gids,
            maximum_frame_bytes=maximum_frame_bytes,
        )

    with pytest.raises(ValueError, match="maximum_frame_bytes"):
        UnixBrokerClient(
            socket_path=tmp_path / "client.sock",
            maximum_frame_bytes=0,
        )


def test_server_rejects_missing_socket_parent(tmp_path: Path) -> None:
    server = UnixBrokerServer(
        socket_path=tmp_path / "missing" / "broker.sock",
        broker=FakeBroker(),
        allowed_uids=frozenset({os.getuid()}),
        allowed_gids=frozenset({os.getgid()}),
    )
    with pytest.raises(RuntimeError, match="parent directory"):
        server.serve_once()


def test_server_hides_unexpected_broker_failure(tmp_path: Path) -> None:
    path = tmp_path / "broker.sock"
    thread, errors = _start(path, ExplodingBroker())
    with pytest.raises(UnixBrokerProtocolError) as raised:
        UnixBrokerClient(socket_path=path).MintReadToken("work-1")
    assert raised.value.code == "INTERNAL_ERROR"
    _finish(thread, errors, path)


def test_server_ready_callback_is_optional(tmp_path: Path) -> None:
    path = tmp_path / "broker.sock"
    errors: list[BaseException] = []
    server = UnixBrokerServer(
        socket_path=path,
        broker=FakeBroker(),
        allowed_uids=frozenset({os.getuid()}),
        allowed_gids=frozenset({os.getgid()}),
    )

    def serve() -> None:
        try:
            server.serve_once()
        except BaseException as exc:
            errors.append(exc)

    thread = Thread(target=serve)
    thread.start()
    for _ in range(200):
        if path.exists():
            break
        time.sleep(0.01)
    assert path.exists()
    result = UnixBrokerClient(socket_path=path).MintReadToken("work-1")
    assert result.repository_id == 123456
    _finish(thread, errors, path)


def test_owned_socket_cleanup_is_conservative(tmp_path: Path) -> None:
    path = tmp_path / "broker.sock"
    server = UnixBrokerServer(
        socket_path=path,
        broker=FakeBroker(),
        allowed_uids=frozenset({os.getuid()}),
        allowed_gids=frozenset({os.getgid()}),
    )
    server._unlink_owned_socket(None)
    server._unlink_owned_socket((1, 1))
    path.write_text("replacement", encoding="utf-8")
    path_stat = path.stat()
    server._unlink_owned_socket((path_stat.st_dev, path_stat.st_ino))
    assert path.read_text(encoding="utf-8") == "replacement"


class _ClientConnection:
    def connect(self, _path: str) -> None:
        return None

    def sendall(self, _value: bytes) -> None:
        return None

    def close(self) -> None:
        return None


@pytest.mark.parametrize(
    "response",
    [
        {"version": 2, "error": "DENIED"},
        {"version": 1, "error": 1},
        {"version": 1, "unexpected": "field"},
        {
            "version": 1,
            "token": "",
            "repository_id": 123456,
            "authorization_version": 7,
            "expires_at": "2026-08-18T13:00:00Z",
        },
    ],
)
def test_client_rejects_malformed_response_shapes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    response: dict[str, object],
) -> None:
    monkeypatch.setattr(socket, "socket", lambda *_: _ClientConnection())
    monkeypatch.setattr(unix_socket, "_receive_mapping", lambda *_a, **_k: response)
    with pytest.raises(UnixBrokerProtocolError, match="MALFORMED_RESPONSE"):
        UnixBrokerClient(socket_path=tmp_path / "broker.sock").MintReadToken("work-1")


@pytest.mark.parametrize(
    "expires_at",
    [
        _MISSING,
        None,
        True,
        "",
        " 2026-08-18T13:00:00Z",
        "not-a-time",
        "not-a-timeZ",
        "2026-08-18T13:00:00",
        "2026-08-18T13:00:00+00:00",
        "2026-08-18T14:00:00+01:00",
        "20260818T130000Z",
    ],
)
def test_client_rejects_missing_malformed_or_non_utc_expiry(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    expires_at: object,
) -> None:
    response: dict[str, object] = {
        "version": 1,
        "token": "opaque",
        "repository_id": 123456,
        "authorization_version": 7,
    }
    if expires_at is not _MISSING:
        response["expires_at"] = expires_at
    monkeypatch.setattr(socket, "socket", lambda *_: _ClientConnection())
    monkeypatch.setattr(unix_socket, "_receive_mapping", lambda *_a, **_k: response)

    with pytest.raises(UnixBrokerProtocolError, match="MALFORMED_RESPONSE"):
        UnixBrokerClient(socket_path=tmp_path / "broker.sock").MintReadToken("work-1")


@pytest.mark.parametrize(
    "expires_at",
    [
        datetime(2026, 8, 18, 13, 0),
        datetime(2026, 8, 18, 14, 0, tzinfo=timezone(timedelta(hours=1))),
    ],
)
def test_server_rejects_non_utc_broker_expiry(
    expires_at: datetime,
) -> None:
    with pytest.raises(UnixBrokerProtocolError, match="INVALID_BROKER_RESULT"):
        unix_socket._format_utc_expiry(expires_at)


class _PeerConnection:
    def __init__(self, value: bytes | BaseException) -> None:
        self.value = value

    def getsockopt(self, *_: object) -> bytes:
        if isinstance(self.value, BaseException):
            raise self.value
        return self.value


def test_peer_credentials_fail_closed_when_unavailable_or_invalid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delattr(socket, "SO_PEERCRED")
    with pytest.raises(UnixBrokerProtocolError, match="PEER_CREDENTIALS_UNAVAILABLE"):
        unix_socket._peer_identity(cast(socket.socket, _PeerConnection(b"")))
    monkeypatch.undo()

    with pytest.raises(UnixBrokerProtocolError, match="PEER_CREDENTIALS_UNAVAILABLE"):
        unix_socket._peer_identity(
            cast(socket.socket, _PeerConnection(OSError("unavailable")))
        )
    with pytest.raises(UnixBrokerProtocolError, match="PEER_CREDENTIALS_INVALID"):
        unix_socket._peer_identity(
            cast(socket.socket, _PeerConnection(struct.pack("3i", 0, 0, 0)))
        )


class _ReceivingConnection:
    def __init__(self, value: bytes) -> None:
        self.value = bytearray(value)

    def recv(self, length: int, flags: int = 0) -> bytes:
        if flags:
            raise BlockingIOError
        chunk = bytes(self.value[:length])
        del self.value[:length]
        return chunk


def test_frame_helpers_reject_non_mapping_oversized_and_truncated_data() -> None:
    body = b"[]"
    framed = struct.pack("!I", len(body)) + body
    with pytest.raises(UnixBrokerProtocolError, match="MALFORMED_JSON"):
        unix_socket._receive_mapping(
            cast(socket.socket, _ReceivingConnection(framed)),
            maximum_frame_bytes=65_536,
        )

    with pytest.raises(UnixBrokerProtocolError, match="FRAME_SIZE_REJECTED"):
        unix_socket._send_mapping(
            cast(socket.socket, _ClientConnection()),
            {"value": "too-long"},
            maximum_frame_bytes=1,
        )

    with pytest.raises(UnixBrokerProtocolError, match="TRUNCATED_FRAME"):
        unix_socket._receive_exact(
            cast(socket.socket, _ReceivingConnection(b"x")),
            2,
        )

    with pytest.raises(ValueError, match="unsupported JSON number"):
        unix_socket._reject_json_number("1.5")
