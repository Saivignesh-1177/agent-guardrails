"""Authorization for LLM agent tool calls (OWASP LLM06: Excessive Agency).

The model only *proposes* a tool call. This module decides whether it runs. It does not trust anything the
model says about itself: decisions depend only on the policy, the arguments, and whether untrusted data has
entered the context (taint).

Decisions:
  allow    run it
  approve  pause for a human (high-risk tool, or tainted context)
  deny     never run it, and tell the model why
"""
import fnmatch
import ipaddress
import posixpath
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from urllib.parse import urlsplit


@dataclass(frozen=True)
class Decision:
    action: str          # allow | approve | deny
    reason: str
    tool: str


@dataclass
class ToolPolicy:
    risk: str = "low"                    # low | high
    allowed_domains: list[str] = field(default_factory=list)   # for args named "url"
    allowed_recipients: list[str] = field(default_factory=list)  # glob patterns for "to"
    sandbox_root: str | None = None      # for args named "path"
    max_calls_per_minute: int = 30
    deny_args: dict[str, list[str]] = field(default_factory=dict)  # arg -> forbidden substrings


class Session:
    """Per-conversation state: taint flag and rate counters."""

    def __init__(self) -> None:
        self.tainted_by: list[str] = []
        self.calls: dict[str, deque] = defaultdict(deque)

    def ingest_untrusted(self, source: str) -> None:
        """Call this whenever web pages, emails, files, or tool output enter the model context."""
        self.tainted_by.append(source)


def _is_private_host(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return host in {"localhost", "metadata.google.internal"} or host.endswith(".internal")
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_unspecified


def _check_url(url: str, allowed: list[str]) -> str | None:
    parts = urlsplit(url)
    if parts.scheme not in ("https",):
        return f"scheme '{parts.scheme}' not allowed (https only)"
    if parts.username or parts.password:
        return "credentials in URL"
    host = (parts.hostname or "").lower()
    if _is_private_host(host):
        return f"internal/metadata host '{host}' blocked (SSRF)"
    if not any(host == d or host.endswith("." + d) for d in allowed):
        return f"domain '{host}' not on allowlist"
    return None


def _check_path(path: str, root: str) -> str | None:
    if "\x00" in path:
        return "NUL byte in path"
    norm = posixpath.normpath(posixpath.join(root, path.replace("\\", "/")))
    if norm != root and not norm.startswith(root.rstrip("/") + "/"):
        return f"path escapes sandbox ({norm})"
    return None


class Guard:
    def __init__(self, policies: dict[str, ToolPolicy], clock=time.monotonic) -> None:
        self.policies = policies
        self.clock = clock

    def check(self, session: Session, tool: str, args: dict) -> Decision:
        pol = self.policies.get(tool)
        if pol is None:
            return Decision("deny", "tool not in policy (default deny)", tool)

        for arg, bad in pol.deny_args.items():
            val = str(args.get(arg, "")).lower()
            hit = next((b for b in bad if b in val), None)
            if hit:
                return Decision("deny", f"argument '{arg}' contains forbidden '{hit}'", tool)
        if "url" in args:
            if err := _check_url(str(args["url"]), pol.allowed_domains):
                return Decision("deny", err, tool)
        if "path" in args:
            if pol.sandbox_root is None:
                return Decision("deny", "path argument but no sandbox configured", tool)
            if err := _check_path(str(args["path"]), pol.sandbox_root):
                return Decision("deny", err, tool)
        if "to" in args:
            recips = args["to"] if isinstance(args["to"], list) else [args["to"]]
            for r in recips:
                if not any(fnmatch.fnmatch(str(r).lower(), p) for p in pol.allowed_recipients):
                    return Decision("deny", f"recipient '{r}' not allowed", tool)

        now = self.clock()
        window = session.calls[tool]
        while window and now - window[0] > 60:
            window.popleft()
        if len(window) >= pol.max_calls_per_minute:
            return Decision("deny", "rate limit exceeded", tool)
        window.append(now)

        if pol.risk == "high":
            return Decision("approve", "high-risk tool requires human approval", tool)
        if session.tainted_by and pol.risk != "low":
            return Decision("approve", "context tainted", tool)
        return Decision("allow", "within policy", tool)


def tainted_escalation(guard: Guard, session: Session, tool: str, args: dict) -> Decision:
    """Stricter mode: once untrusted content is in context, every side-effecting tool needs approval.

    Read-only tools are still allowed. This is the "dual LLM" / CaMeL idea in its simplest form.
    """
    d = guard.check(session, tool, args)
    if d.action == "allow" and session.tainted_by and not tool.startswith(("read_", "search_", "get_")):
        return Decision("approve", f"side effect after untrusted input from {session.tainted_by[-1]}", tool)
    return d
