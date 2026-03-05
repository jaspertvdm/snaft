"""
SNAFT Storage — JSON persistence for rules and agent trust state.

Simple, file-based persistence.
No database dependency. No external services. Just files.
"""

import json
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from .identity import AgentIdentity, AgentState, FIRAScore

# Default storage directory
DEFAULT_STORAGE_DIR = os.path.expanduser("~/.snaft")


class Storage:
    """File-based persistence for SNAFT state."""

    def __init__(self, storage_dir: Optional[str] = None):
        self._dir = Path(storage_dir or DEFAULT_STORAGE_DIR)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._rules_file = self._dir / "rules.json"
        self._agents_file = self._dir / "agents.json"
        self._config_file = self._dir / "config.json"
        self._log_dir = self._dir / "logs"
        self._log_dir.mkdir(exist_ok=True)

    # =========================================================================
    # CONFIG
    # =========================================================================

    def load_config(self) -> Dict[str, Any]:
        """Load firewall configuration."""
        if self._config_file.exists():
            with open(self._config_file) as f:
                return json.load(f)
        return {
            "default_policy": "deny",
            "fail_mode": "closed",
            "enabled": True,
        }

    def save_config(self, config: Dict[str, Any]) -> None:
        """Save firewall configuration."""
        with open(self._config_file, "w") as f:
            json.dump(config, f, indent=2)

    # =========================================================================
    # RULES (custom rules only — poison rules are code, not config)
    # =========================================================================

    def load_rules(self) -> List[Dict[str, Any]]:
        """Load custom rules from disk."""
        if self._rules_file.exists():
            with open(self._rules_file) as f:
                return json.load(f)
        return []

    def save_rules(self, rules: List[Dict[str, Any]]) -> None:
        """Save custom rules to disk."""
        with open(self._rules_file, "w") as f:
            json.dump(rules, f, indent=2)

    # =========================================================================
    # AGENTS
    # =========================================================================

    def load_agents(self) -> Dict[str, AgentIdentity]:
        """Load agent identities from disk."""
        if not self._agents_file.exists():
            return {}
        with open(self._agents_file) as f:
            data = json.load(f)

        agents = {}
        for name, d in data.items():
            fira = FIRAScore(
                frequency=d.get("fira", {}).get("frequency", 0.5),
                integrity=d.get("fira", {}).get("integrity", 0.5),
                recency=d.get("fira", {}).get("recency", 1.0),
                anomaly=d.get("fira", {}).get("anomaly", 0.0),
            )
            agent = AgentIdentity(
                name=name,
                fira=fira,
                state=AgentState(d.get("state", "unknown")),
                created_at=d.get("created_at", time.time()),
                last_action_at=d.get("last_action_at", 0.0),
                total_actions=d.get("total_actions", 0),
                allowed_actions=d.get("allowed", 0),
                blocked_actions=d.get("blocked", 0),
                warned_actions=d.get("warned", 0),
                consecutive_blocks=d.get("consecutive_blocks", 0),
            )
            agents[name] = agent
        return agents

    def save_agents(self, agents: Dict[str, AgentIdentity]) -> None:
        """Save agent identities to disk."""
        data = {}
        for name, agent in agents.items():
            data[name] = agent.to_dict()
            data[name]["created_at"] = agent.created_at
            data[name]["last_action_at"] = agent.last_action_at
        with open(self._agents_file, "w") as f:
            json.dump(data, f, indent=2)

    # =========================================================================
    # AUDIT LOG
    # =========================================================================

    def append_log(self, entry: Dict[str, Any]) -> None:
        """Append an audit log entry to today's log file."""
        today = time.strftime("%Y-%m-%d")
        log_file = self._log_dir / f"{today}.jsonl"
        with open(log_file, "a") as f:
            f.write(json.dumps(entry) + "\n")

    def read_log(self, date: Optional[str] = None, last_n: int = 50) -> List[Dict]:
        """Read audit log entries."""
        if date is None:
            date = time.strftime("%Y-%m-%d")
        log_file = self._log_dir / f"{date}.jsonl"
        if not log_file.exists():
            return []
        entries = []
        with open(log_file) as f:
            for line in f:
                line = line.strip()
                if line:
                    entries.append(json.loads(line))
        return entries[-last_n:]

    def log_files(self) -> List[str]:
        """List available log dates."""
        return sorted(f.stem for f in self._log_dir.glob("*.jsonl"))

    # =========================================================================
    # UTILS
    # =========================================================================

    @property
    def storage_dir(self) -> str:
        return str(self._dir)

    def wipe(self, confirm: bool = False) -> bool:
        """Wipe all stored state. Requires explicit confirmation."""
        if not confirm:
            return False
        for f in [self._rules_file, self._agents_file, self._config_file]:
            if f.exists():
                f.unlink()
        for f in self._log_dir.glob("*.jsonl"):
            f.unlink()
        return True
