"""Tamper-evident append-only audit chain.

Only metadata is stored here. Secrets, tokens, credentials and raw payloads
must never be written to the chain.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from pathlib import Path


class AuditChain:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            self.path.parent.chmod(0o700)
        except OSError:
            pass
        if self.path.exists():
            try:
                self.path.chmod(0o600)
            except OSError:
                pass
        self._lock = threading.Lock()

    @staticmethod
    def _canonical(record: dict[str, object]) -> bytes:
        return json.dumps(
            record,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    def append(
        self,
        *,
        event: str,
        actor: str,
        outcome: str,
        request_id: str,
    ) -> str:
        if not all((event, actor, outcome, request_id)):
            raise ValueError("audit fields must not be empty")

        with self._lock:
            previous = "0" * 64

            if self.path.exists():
                try:
                    with self.path.open("rb") as handle:
                        for line in handle:
                            if not line.strip():
                                continue

                            item = json.loads(line)
                            if not isinstance(item, dict):
                                raise ValueError("audit chain contains a non-object record")

                            supplied = item.get("hash")
                            if not isinstance(supplied, str):
                                raise ValueError("audit chain record is missing a valid hash")

                            if len(supplied) != 64 or any(
                                character not in "0123456789abcdef"
                                for character in supplied
                            ):
                                raise ValueError("audit chain record contains an invalid hash")

                            previous = supplied

                except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
                    raise ValueError("audit chain is malformed; append refused") from exc

            record = {
                "timestamp": int(time.time()),
                "event": event,
                "actor": actor,
                "outcome": outcome,
                "request_id": request_id,
                "previous_hash": previous,
            }

            digest = hashlib.sha256(
                previous.encode("ascii") + self._canonical(record)
            ).hexdigest()

            record["hash"] = digest

            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(
                    json.dumps(
                        record,
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                    + "\n"
                )

            return digest

    def verify(self) -> bool:
        if not self.path.exists():
            return True

        previous = "0" * 64

        try:
            with self.path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    if not line.strip():
                        continue

                    item = json.loads(line)
                    if not isinstance(item, dict):
                        return False

                    supplied = item.pop("hash", None)
                    if not isinstance(supplied, str):
                        return False

                    if len(supplied) != 64:
                        return False

                    if any(
                        character not in "0123456789abcdef"
                        for character in supplied
                    ):
                        return False

                    if item.get("previous_hash") != previous:
                        return False

                    expected = hashlib.sha256(
                        previous.encode("ascii") + self._canonical(item)
                    ).hexdigest()

                    if not hmac_compare(expected, supplied):
                        return False

                    previous = supplied

        except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
            return False

        return True



def hmac_compare(left: str, right: str) -> bool:
    import hmac

    return hmac.compare_digest(left, right)
