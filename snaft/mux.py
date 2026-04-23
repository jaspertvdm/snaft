"""
SNAFT MUX — Null-Route Detection Engine.

"De Kat en de Red Baron"

Detecteert abnormaal verkeer per IP via dual-threshold analyse:
rate limiting + patroonherkenning. Wanneer getriggerd wordt de
aanvaller gemuxed naar 0x00 — stilte. Geen response, geen status
code, geen informatie. Hun buffer loopt vol, wij leren.

Kat op toetsenbord = gestructureerde aanval = zelfde behandeling.

Usage:
    from snaft.mux import NullRouteMux

    mux = NullRouteMux()
    decision = mux.check("185.131.15.134", "/api/ains/lookup", "GET")

    if decision.should_null_route:
        # Hold connection open, send nothing
        mux.absorb(ip, path, method, headers, body)
"""

import math
import time
from collections import Counter, deque
from dataclasses import dataclass, field
from ipaddress import ip_address, ip_network
from typing import Dict, List, Optional, Set

from .identity import FIRAScore

__all__ = [
    "NullRouteMux",
    "NullRouteDecision",
    "IPProfile",
]

# Default whitelist: localhost + internal + known external
_DEFAULT_WHITELIST = [
    "127.0.0.1",
    "::1",
    "192.168.4.0/24",   # Internal LAN (DL360, P520, etc.)
    "10.0.100.0/24",    # VPN / overlay
    "84.86.71.6",       # Jasper extern (Ziggo)
    # Emigreen / Nikolaos — toevoegen wanneer TIBET live gaat
    # "x.x.x.x",        # Emigreen kantoor
]


def _shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string (bits per char)."""
    if not s:
        return 0.0
    freq = Counter(s)
    length = len(s)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in freq.values()
    )


@dataclass
class IPProfile:
    """Per-IP behavioral profile for MUX decisions."""

    ip: str
    request_timestamps: deque = field(default_factory=lambda: deque(maxlen=100))
    path_history: deque = field(default_factory=lambda: deque(maxlen=20))
    null_routed: bool = False
    null_routed_at: float = 0.0
    offense_count: int = 0
    total_absorbed: int = 0
    active_holds: int = 0
    high_entropy_count: int = 0
    fira: FIRAScore = field(default_factory=FIRAScore)

    # What we learn while they're null-routed
    absorbed_paths: Counter = field(default_factory=Counter)
    absorbed_methods: Counter = field(default_factory=Counter)
    absorbed_bodies: list = field(default_factory=list)
    absorbed_headers: list = field(default_factory=list)

    def requests_in_window(self, window_seconds: float) -> int:
        """Count requests in the last N seconds."""
        cutoff = time.monotonic() - window_seconds
        return sum(1 for ts in self.request_timestamps if ts > cutoff)

    def most_common_path(self, n: int = 10) -> Optional[tuple]:
        """Most repeated path in recent history."""
        if not self.path_history:
            return None
        counter = Counter(self.path_history)
        most = counter.most_common(1)[0]
        return most  # (path, count)

    def absorbed_summary(self) -> dict:
        """Summary of absorbed traffic for triage flare."""
        return {
            "total_absorbed": self.total_absorbed,
            "offense_count": self.offense_count,
            "top_paths": dict(self.absorbed_paths.most_common(10)),
            "methods": dict(self.absorbed_methods),
            "sample_bodies": self.absorbed_bodies[:5],
            "fira": self.fira.to_dict(),
            "null_routed_since": self.null_routed_at,
            "duration_seconds": round(time.monotonic() - self.null_routed_at, 1)
            if self.null_routed_at else 0,
        }


@dataclass
class NullRouteDecision:
    """Result of a MUX check."""

    should_null_route: bool
    reason: str = ""
    is_new_trigger: bool = False  # True only on first trigger (fire flare once)
    profile: Optional[IPProfile] = None

    @property
    def fira_score(self) -> float:
        if self.profile:
            return self.profile.fira.score
        return 0.0


class NullRouteMux:
    """Null-route detection engine.

    Tracks per-IP request patterns and decides when to mux
    traffic to 0x00 (silence).

    Args:
        rate_threshold: Max requests per window before null-route.
        window_seconds: Sliding window size for rate detection.
        repetition_threshold: Same-path hits in last N before null-route.
        entropy_threshold: Shannon entropy bits/char that flags fuzzing.
        entropy_strikes: High-entropy requests before null-route.
        hold_duration: Seconds to hold null-routed connections.
        max_holds_per_ip: Max concurrent holds per IP.
        whitelist: List of IPs/CIDRs to never null-route.
    """

    def __init__(
        self,
        rate_threshold: int = 15,
        window_seconds: float = 10.0,
        repetition_threshold: int = 5,
        entropy_threshold: float = 4.0,
        entropy_strikes: int = 3,
        hold_duration: float = 120.0,
        max_holds_per_ip: int = 10,
        whitelist: Optional[List[str]] = None,
    ):
        self.rate_threshold = rate_threshold
        self.window_seconds = window_seconds
        self.repetition_threshold = repetition_threshold
        self.entropy_threshold = entropy_threshold
        self.entropy_strikes = entropy_strikes
        self.hold_duration = hold_duration
        self.max_holds_per_ip = max_holds_per_ip

        # Parse whitelist into networks
        raw = whitelist or _DEFAULT_WHITELIST
        self._whitelist_networks = []
        self._whitelist_ips: Set[str] = set()
        for entry in raw:
            if "/" in entry:
                self._whitelist_networks.append(ip_network(entry, strict=False))
            else:
                self._whitelist_ips.add(entry)

        # Per-IP profiles
        self._profiles: Dict[str, IPProfile] = {}

        # Global counters
        self.total_null_routed = 0
        self.total_absorbed = 0
        self.flares_sent = 0

    def _is_whitelisted(self, ip: str) -> bool:
        if ip in self._whitelist_ips:
            return True
        try:
            addr = ip_address(ip)
            return any(addr in net for net in self._whitelist_networks)
        except ValueError:
            return False

    def _get_profile(self, ip: str) -> IPProfile:
        if ip not in self._profiles:
            self._profiles[ip] = IPProfile(ip=ip)
        return self._profiles[ip]

    def check(self, ip: str, path: str, method: str = "GET") -> NullRouteDecision:
        """Check if an IP should be null-routed.

        Returns NullRouteDecision with routing decision and reason.
        """
        # Whitelisted IPs always pass
        if self._is_whitelisted(ip):
            return NullRouteDecision(should_null_route=False)

        # Exempt paths (health checks, monitoring)
        if path in ("/health", "/", "/favicon.ico"):
            return NullRouteDecision(should_null_route=False)

        profile = self._get_profile(ip)

        # Already null-routed — stay null-routed
        if profile.null_routed:
            profile.total_absorbed += 1
            self.total_absorbed += 1
            return NullRouteDecision(
                should_null_route=True,
                reason=f"already null-routed (offense #{profile.offense_count})",
                is_new_trigger=False,
                profile=profile,
            )

        # Record this request
        now = time.monotonic()
        profile.request_timestamps.append(now)
        profile.path_history.append(path)

        # === Check 1: Rate threshold ===
        req_count = profile.requests_in_window(self.window_seconds)
        if req_count > self.rate_threshold:
            return self._trigger(
                profile,
                f"rate exceeded: {req_count} requests in {self.window_seconds}s "
                f"(threshold: {self.rate_threshold})",
            )

        # === Check 2: Path repetition ===
        most_common = profile.most_common_path()
        if most_common and most_common[1] >= self.repetition_threshold:
            return self._trigger(
                profile,
                f"path repetition: {most_common[0]} hit {most_common[1]}x "
                f"in last {len(profile.path_history)} requests",
            )

        # === Check 3: High entropy (fuzzing / cat on keyboard) ===
        # Check path segments for randomness
        segments = [s for s in path.split("/") if s and len(s) > 8]
        for segment in segments:
            entropy = _shannon_entropy(segment)
            if entropy > self.entropy_threshold:
                profile.high_entropy_count += 1
                break

        if profile.high_entropy_count >= self.entropy_strikes:
            return self._trigger(
                profile,
                f"high entropy: {profile.high_entropy_count} fuzzing-like "
                f"path segments detected (threshold: {self.entropy_strikes})",
            )

        # Clean traffic — reward slightly
        profile.fira.integrity = min(1.0, profile.fira.integrity + 0.005)
        profile.fira.anomaly = max(0.0, profile.fira.anomaly - 0.002)

        return NullRouteDecision(
            should_null_route=False,
            profile=profile,
        )

    def _trigger(self, profile: IPProfile, reason: str) -> NullRouteDecision:
        """Activate null-route for an IP."""
        profile.null_routed = True
        profile.null_routed_at = time.monotonic()
        profile.offense_count += 1
        self.total_null_routed += 1

        # Penalize FIR/A hard
        profile.fira.integrity = max(0.0, profile.fira.integrity - 0.3)
        profile.fira.anomaly = min(1.0, profile.fira.anomaly + 0.4)
        profile.fira.frequency = max(0.0, profile.fira.frequency - 0.2)

        return NullRouteDecision(
            should_null_route=True,
            reason=reason,
            is_new_trigger=True,
            profile=profile,
        )

    def absorb(
        self,
        ip: str,
        path: str,
        method: str,
        headers: Optional[dict] = None,
        body: Optional[bytes] = None,
    ) -> None:
        """Record absorbed request data (we learn, they don't)."""
        profile = self._get_profile(ip)
        profile.absorbed_paths[path] += 1
        profile.absorbed_methods[method] += 1

        if body and len(profile.absorbed_bodies) < 50:
            profile.absorbed_bodies.append(body[:1024].decode("utf-8", errors="replace"))

        if headers and len(profile.absorbed_headers) < 20:
            profile.absorbed_headers.append(headers)

    def get_profile(self, ip: str) -> Optional[IPProfile]:
        return self._profiles.get(ip)

    def get_absorbed_summary(self, ip: str) -> dict:
        profile = self._profiles.get(ip)
        if not profile:
            return {}
        return profile.absorbed_summary()

    def get_all_null_routed(self) -> List[IPProfile]:
        return [p for p in self._profiles.values() if p.null_routed]

    def release(self, ip: str) -> bool:
        """Manually un-null-route an IP (for Root AI commands)."""
        profile = self._profiles.get(ip)
        if profile and profile.null_routed:
            profile.null_routed = False
            profile.null_routed_at = 0.0
            return True
        return False

    def metrics(self) -> dict:
        """Global MUX metrics."""
        null_routed = self.get_all_null_routed()
        return {
            "enabled": True,
            "total_ips_tracked": len(self._profiles),
            "total_null_routed": len(null_routed),
            "total_absorbed_requests": self.total_absorbed,
            "total_triggers": self.total_null_routed,
            "flares_sent": self.flares_sent,
            "null_routed_ips": [
                {
                    "ip": p.ip,
                    "offense_count": p.offense_count,
                    "absorbed": p.total_absorbed,
                    "fira": p.fira.to_dict(),
                    "top_paths": dict(p.absorbed_paths.most_common(5)),
                }
                for p in null_routed
            ],
            "config": {
                "rate_threshold": self.rate_threshold,
                "window_seconds": self.window_seconds,
                "repetition_threshold": self.repetition_threshold,
                "hold_duration": self.hold_duration,
            },
        }

    def cleanup_stale(self, max_age_seconds: float = 3600.0) -> int:
        """Remove profiles with no activity for max_age_seconds."""
        cutoff = time.monotonic() - max_age_seconds
        stale = [
            ip for ip, p in self._profiles.items()
            if not p.null_routed
            and (not p.request_timestamps or p.request_timestamps[-1] < cutoff)
        ]
        for ip in stale:
            del self._profiles[ip]
        return len(stale)
