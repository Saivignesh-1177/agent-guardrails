"""Tamper-evident audit log: every record carries the HMAC of the previous record.

If anyone edits, deletes, or reorders a past entry, for example to hide what an agent did, verify() points
to the first broken link. The key should live outside the agent's reach (KMS / Key Vault).
"""
import hashlib
import hmac
import json
import time

GENESIS = "0" * 64


class AuditLog:
    def __init__(self, key: bytes) -> None:
        self._key = key
        self.records: list[dict] = []

    def _mac(self, body: dict) -> str:
        msg = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
        return hmac.new(self._key, msg, hashlib.sha256).hexdigest()

    def append(self, event: dict) -> dict:
        prev = self.records[-1]["mac"] if self.records else GENESIS
        body = {"seq": len(self.records), "ts": time.time(), "prev": prev, "event": event}
        rec = {**body, "mac": self._mac(body)}
        self.records.append(rec)
        return rec

    def verify(self) -> int | None:
        """Return the index of the first invalid record, or None if the chain is intact."""
        prev = GENESIS
        for i, rec in enumerate(self.records):
            body = {k: rec[k] for k in ("seq", "ts", "prev", "event")}
            if rec["seq"] != i or rec["prev"] != prev or not hmac.compare_digest(rec["mac"], self._mac(body)):
                return i
            prev = rec["mac"]
        return None
