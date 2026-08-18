"""Bounded version-1 AF_UNIX interface for MintReadToken."""

from __future__ import annotations

import json
import os
import socket
import stat
import struct
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Protocol

from github_steward.ports.secrets import OpaqueBearerToken

from .credential_broker import CredentialBrokerError, MintReadTokenResult

PROTOCOL_VERSION: Final = 1
MAX_FRAME_BYTES: Final = 65_536
_HEADER_BYTES: Final = 4


class ReadTokenBroker(Protocol):
    def MintReadToken(self, work_record_id: str) -> MintReadTokenResult: ...


@dataclass(frozen=True, slots=True)
class UnixMintReadTokenResult:
    token: OpaqueBearerToken
    repository_id: int
    authorization_version: int


@dataclass(frozen=True, slots=True)
class UnixPeerIdentity:
    pid: int
    uid: int
    gid: int


class UnixBrokerProtocolError(RuntimeError):
    """A safe local-protocol error that never incorporates request secrets."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class UnixBrokerServer:
    """Serve one bounded local request; no daemon or TCP surface is provided."""

    def __init__(
        self,
        *,
        socket_path: str | Path,
        broker: ReadTokenBroker,
        allowed_uids: frozenset[int],
        allowed_gids: frozenset[int],
        maximum_frame_bytes: int = MAX_FRAME_BYTES,
    ) -> None:
        path = Path(socket_path)
        if not path.is_absolute() or path.name in {"", ".", ".."}:
            raise ValueError("socket_path must be an absolute file path")
        if not allowed_uids or not allowed_gids:
            raise ValueError("at least one allowed UID and GID is required")
        if any(value < 0 for value in (*allowed_uids, *allowed_gids)):
            raise ValueError("UIDs and GIDs must be non-negative")
        if maximum_frame_bytes < 1:
            raise ValueError("maximum_frame_bytes must be positive")
        self._path = path
        self._broker = broker
        self._allowed_uids = allowed_uids
        self._allowed_gids = allowed_gids
        self._maximum_frame_bytes = maximum_frame_bytes

    @property
    def socket_family(self) -> int:
        return socket.AF_UNIX

    def serve_once(self, *, ready: Callable[[], None] | None = None) -> None:
        """Bind, authorize one peer by UID+GID, answer once, and clean up."""

        if self._path.exists() or self._path.is_symlink():
            raise RuntimeError("broker socket path already exists")
        if not self._path.parent.is_dir():
            raise RuntimeError("broker socket parent directory does not exist")
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        owned_identity: tuple[int, int] | None = None
        try:
            listener.bind(str(self._path))
            os.chmod(self._path, 0o660)
            path_stat = self._path.lstat()
            owned_identity = (path_stat.st_dev, path_stat.st_ino)
            listener.listen(1)
            if ready is not None:
                ready()
            connection, _ = listener.accept()
            with connection:
                try:
                    peer = _peer_identity(connection)
                    if (
                        peer.uid not in self._allowed_uids
                        or peer.gid not in self._allowed_gids
                    ):
                        raise UnixBrokerProtocolError("PEER_NOT_AUTHORIZED")
                    request = _receive_mapping(
                        connection,
                        maximum_frame_bytes=self._maximum_frame_bytes,
                    )
                    work_record_id = _request_work_record_id(request)
                    result = self._broker.MintReadToken(work_record_id)
                    response: dict[str, object] = {
                        "version": PROTOCOL_VERSION,
                        "token": result.token._authorized_broker_wire_value(),
                        "repository_id": result.repository_id,
                        "authorization_version": result.authorization_version,
                    }
                except CredentialBrokerError as exc:
                    response = {
                        "version": PROTOCOL_VERSION,
                        "error": exc.code.value,
                    }
                except UnixBrokerProtocolError as exc:
                    response = {"version": PROTOCOL_VERSION, "error": exc.code}
                except Exception:
                    response = {
                        "version": PROTOCOL_VERSION,
                        "error": "INTERNAL_ERROR",
                    }
                _send_mapping(
                    connection,
                    response,
                    maximum_frame_bytes=self._maximum_frame_bytes,
                )
        finally:
            listener.close()
            self._unlink_owned_socket(owned_identity)

    def _unlink_owned_socket(self, owned_identity: tuple[int, int] | None) -> None:
        if owned_identity is None:
            return
        try:
            path_stat = self._path.lstat()
        except FileNotFoundError:
            return
        if (
            stat.S_ISSOCK(path_stat.st_mode)
            and (path_stat.st_dev, path_stat.st_ino) == owned_identity
        ):
            self._path.unlink()


class UnixBrokerClient:
    """Strict version-1 client used by the authenticated acquisition boundary."""

    def __init__(
        self,
        *,
        socket_path: str | Path,
        maximum_frame_bytes: int = MAX_FRAME_BYTES,
    ) -> None:
        path = Path(socket_path)
        if not path.is_absolute():
            raise ValueError("socket_path must be absolute")
        if maximum_frame_bytes < 1:
            raise ValueError("maximum_frame_bytes must be positive")
        self._path = path
        self._maximum_frame_bytes = maximum_frame_bytes

    @property
    def socket_family(self) -> int:
        return socket.AF_UNIX

    def MintReadToken(self, work_record_id: str) -> UnixMintReadTokenResult:
        request = {"version": PROTOCOL_VERSION, "work_record_id": work_record_id}
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            connection.connect(str(self._path))
            _send_mapping(
                connection,
                request,
                maximum_frame_bytes=self._maximum_frame_bytes,
            )
            response = _receive_mapping(
                connection,
                maximum_frame_bytes=self._maximum_frame_bytes,
            )
        finally:
            connection.close()
        if set(response) == {"version", "error"}:
            if response.get("version") != PROTOCOL_VERSION or not isinstance(
                response.get("error"), str
            ):
                raise UnixBrokerProtocolError("MALFORMED_RESPONSE")
            raise UnixBrokerProtocolError(str(response["error"]))
        if set(response) != {
            "version",
            "token",
            "repository_id",
            "authorization_version",
        }:
            raise UnixBrokerProtocolError("MALFORMED_RESPONSE")
        version = response["version"]
        token = response["token"]
        repository_id = response["repository_id"]
        authorization_version = response["authorization_version"]
        if (
            isinstance(version, bool)
            or version != PROTOCOL_VERSION
            or not isinstance(token, str)
            or token == ""
            or isinstance(repository_id, bool)
            or not isinstance(repository_id, int)
            or repository_id < 1
            or isinstance(authorization_version, bool)
            or not isinstance(authorization_version, int)
            or authorization_version < 1
        ):
            raise UnixBrokerProtocolError("MALFORMED_RESPONSE")
        return UnixMintReadTokenResult(
            OpaqueBearerToken(token),
            repository_id,
            authorization_version,
        )


def _peer_identity(connection: socket.socket) -> UnixPeerIdentity:
    option = getattr(socket, "SO_PEERCRED", None)
    if option is None:
        raise UnixBrokerProtocolError("PEER_CREDENTIALS_UNAVAILABLE")
    try:
        raw = connection.getsockopt(socket.SOL_SOCKET, option, struct.calcsize("3i"))
        pid, uid, gid = struct.unpack("3i", raw)
    except (OSError, struct.error) as exc:
        raise UnixBrokerProtocolError("PEER_CREDENTIALS_UNAVAILABLE") from exc
    if pid < 1 or uid < 0 or gid < 0:
        raise UnixBrokerProtocolError("PEER_CREDENTIALS_INVALID")
    return UnixPeerIdentity(pid, uid, gid)


def _request_work_record_id(value: dict[str, object]) -> str:
    if set(value) != {"version", "work_record_id"}:
        raise UnixBrokerProtocolError("UNKNOWN_OR_MISSING_FIELD")
    version = value["version"]
    work_record_id = value["work_record_id"]
    if isinstance(version, bool) or version != PROTOCOL_VERSION:
        raise UnixBrokerProtocolError("UNSUPPORTED_VERSION")
    if (
        not isinstance(work_record_id, str)
        or work_record_id == ""
        or len(work_record_id.encode("utf-8")) > 256
        or "\x00" in work_record_id
    ):
        raise UnixBrokerProtocolError("INVALID_WORK_RECORD_ID")
    return work_record_id


def _receive_mapping(
    connection: socket.socket,
    *,
    maximum_frame_bytes: int,
) -> dict[str, object]:
    header = _receive_exact(connection, _HEADER_BYTES)
    length = struct.unpack("!I", header)[0]
    if length < 1 or length > maximum_frame_bytes:
        raise UnixBrokerProtocolError("FRAME_SIZE_REJECTED")
    raw = _receive_exact(connection, length)
    try:
        extra = connection.recv(1, socket.MSG_PEEK | socket.MSG_DONTWAIT)
    except (BlockingIOError, ConnectionResetError):
        extra = b""
    if extra:
        raise UnixBrokerProtocolError("MULTIPLE_REQUESTS_REJECTED")
    try:
        text = raw.decode("utf-8", errors="strict")
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_float=_reject_json_number,
            parse_constant=_reject_json_number,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise UnixBrokerProtocolError("MALFORMED_JSON") from exc
    if not isinstance(value, dict):
        raise UnixBrokerProtocolError("MALFORMED_JSON")
    return value


def _send_mapping(
    connection: socket.socket,
    value: dict[str, object],
    *,
    maximum_frame_bytes: int,
) -> None:
    raw = json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    if len(raw) > maximum_frame_bytes:
        raise UnixBrokerProtocolError("FRAME_SIZE_REJECTED")
    connection.sendall(struct.pack("!I", len(raw)) + raw)


def _receive_exact(connection: socket.socket, length: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < length:
        chunk = connection.recv(length - len(chunks))
        if chunk == b"":
            raise UnixBrokerProtocolError("TRUNCATED_FRAME")
        chunks.extend(chunk)
    return bytes(chunks)


def _reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_json_number(_: str) -> object:
    raise ValueError("unsupported JSON number")
