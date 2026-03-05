"""
SNAFT CLI — ufw-style command interface for the AI behavioral firewall.

Usage:
    snaft status                          Show firewall status
    snaft enable                          Enable the firewall
    snaft disable                         Disable the firewall

    snaft rule list                       List all custom rules
    snaft rule add <name> <action> <pattern> [--priority N] [--description "..."]
    snaft rule remove <name>              Remove a custom rule

    snaft check <agent> <action> <intent> Check an action against the firewall
    snaft log [--last N] [--agent X] [--blocked]
                                          Show audit log

    snaft agent list                      List registered agents
    snaft agent show <name>               Show agent details
    snaft agent isolate <name> [reason]   Isolate an agent
    snaft agent reinstate <name>          Reinstate an isolated agent

    snaft version                         Show version info
    snaft reset                           Reset all state (requires --confirm)
"""

import argparse
import json
import sys
import time
from typing import List, Optional

from . import __version__
from .compliance import AuditCategory, ComplianceEngine, RiskLevel
from .firewall import Action, Firewall, Rule
from .identity import AgentIdentity
from .storage import Storage


# ANSI colors for terminal output
class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"


def _colored(text: str, color: str) -> str:
    """Wrap text in ANSI color codes."""
    if not sys.stdout.isatty():
        return text
    return f"{color}{text}{C.RESET}"


def _bold(text: str) -> str:
    return _colored(text, C.BOLD)


def _success(text: str) -> str:
    return _colored(text, C.GREEN)


def _error(text: str) -> str:
    return _colored(text, C.RED)


def _warn(text: str) -> str:
    return _colored(text, C.YELLOW)


def _info(text: str) -> str:
    return _colored(text, C.CYAN)


def _dim(text: str) -> str:
    return _colored(text, C.DIM)


# =============================================================================
# FIREWALL INSTANCE (singleton per CLI invocation)
# =============================================================================

def _load_firewall(storage_dir: Optional[str] = None) -> tuple:
    """Load firewall with persisted state."""
    storage = Storage(storage_dir=storage_dir)
    config = storage.load_config()

    fw = Firewall(
        default_policy=config.get("default_policy", "deny"),
        fail_mode=config.get("fail_mode", "closed"),
    )
    fw._enabled = config.get("enabled", True)

    # Load custom rules
    for rd in storage.load_rules():
        pattern = rd.get("pattern", "")
        rule = Rule(
            name=rd["name"],
            description=rd.get("description", ""),
            action=Action(rd.get("action", "BLOCK")),
            priority=rd.get("priority", 100),
            check=_make_pattern_check(pattern, rd.get("match_field", "intent")),
        )
        rule._pattern = pattern  # Store for serialization
        rule._match_field = rd.get("match_field", "intent")
        fw.add_rule(rule)

    # Load agents
    agents = storage.load_agents()
    for agent in agents.values():
        fw.register_agent(agent)

    return fw, storage


def _save_state(fw: Firewall, storage: Storage) -> None:
    """Persist current state."""
    storage.save_config({
        "default_policy": fw._default_policy,
        "fail_mode": fw._fail_mode,
        "enabled": fw._enabled,
    })
    storage.save_agents(fw._agents)


def _make_pattern_check(pattern: str, match_field: str = "intent"):
    """Create a rule check function from a pattern string."""
    import re
    compiled = re.compile(pattern, re.IGNORECASE)

    def check(agent_id: str, erin, erachter: str) -> bool:
        if match_field == "action":
            return bool(compiled.search(str(erin)))
        elif match_field == "both":
            return bool(compiled.search(str(erin)) or compiled.search(erachter))
        else:  # intent
            return bool(compiled.search(erachter))

    return check


# =============================================================================
# COMMANDS
# =============================================================================

def cmd_status(args):
    """Show firewall status."""
    fw, storage = _load_firewall(args.storage_dir)
    s = fw.status()

    print()
    print(f"  {_bold('SNAFT')} — Semantic Network-Aware Firewall for Trust")
    print(f"  {_dim('Not a guardrail. An immune system.')}")
    print()

    # Status line
    if s["enabled"]:
        print(f"  Status:         {_success('active')}")
    else:
        print(f"  Status:         {_error('inactive')}")

    print(f"  Default policy: {_warn(s['default_policy'])}")
    print(f"  Fail mode:      {s['fail_mode']}")

    backend = s.get("kernel_backend", "python")
    if backend == "rust":
        print(f"  Kernel:         {_success('rust')} {_dim('(compiled, tamper-resistant)')}")
    else:
        print(f"  Kernel:         {_warn('python')} {_dim('(fallback — install snaft-core for Rust)')}")

    print(f"  Rules:          {s['rules_custom']} custom + {s['rules_core']} core (immutable)")
    print(f"  Provenance:     {s['provenance_depth']} tokens in chain")
    print(f"  Storage:        {storage.storage_dir}")

    # Compliance
    comp = s.get("compliance")
    if comp and comp.get("enabled"):
        print()
        print(f"  {_bold('EU AI Act Compliance:')}")
        print(f"    Status:       {_success('active')}")
        print(f"    Risk level:   {_warn(comp['risk_level'])}")
        print(f"    Retention:    {comp['retention_days']} days {_dim('(Art. 26 min: 180)')}")
        print(f"    Records:      {comp['audit_records']}")
        print(f"    Regulation:   {_dim(comp['eu_ai_act'])}")
        print(f"    Enforcement:  {_dim(comp['enforcement'])}")

    print()

    # Agents
    if s["agents"]:
        print(f"  {_bold('Agents:')}")
        for name, info in s["agents"].items():
            state = info["state"]
            trust = info["trust"]
            state_str = _state_colored(state)

            trust_bar = _trust_bar(trust)
            print(f"    {name:20s}  {state_str:10s}  trust={trust:.2f} {trust_bar}  "
                  f"actions={info['actions']} blocked={info['blocked']}")
        print()
    else:
        print(f"  {_dim('No agents registered yet.')}")
        print()


def cmd_enable(args):
    """Enable the firewall."""
    fw, storage = _load_firewall(args.storage_dir)
    fw._enabled = True
    _save_state(fw, storage)
    print(_success("SNAFT firewall enabled"))


def cmd_disable(args):
    """Disable the firewall."""
    fw, storage = _load_firewall(args.storage_dir)
    fw._enabled = False
    _save_state(fw, storage)
    print(_warn("SNAFT firewall disabled"))


def cmd_rule_list(args):
    """List rules."""
    fw, storage = _load_firewall(args.storage_dir)

    custom_rules = [r for r in fw._rules if not r._poison]
    core_rules = [r for r in fw._rules if r._poison]

    print()
    print(f"  {_bold('Custom Rules')} ({len(custom_rules)}):")
    if custom_rules:
        for r in custom_rules:
            action_str = _action_colored(r.action.value)
            print(f"    [{r.priority:3d}] {r.name:30s} {action_str:6s}  {r.description}")
    else:
        print(f"    {_dim('No custom rules. Add with: snaft rule add <name> <action> <pattern>')}")

    print()
    print(f"  {_bold('Core Rules')} ({len(core_rules)}, immutable):")
    for r in core_rules:
        action_str = _action_colored(r.action.value)
        print(f"    [{r.priority:3d}] {r.name:30s} {action_str:6s}  {r.description}")
    print()


def cmd_rule_add(args):
    """Add a custom rule."""
    fw, storage = _load_firewall(args.storage_dir)

    action = Action(args.action.upper())
    pattern = args.pattern

    rule = Rule(
        name=args.name,
        description=args.description or f"Pattern: {pattern}",
        action=action,
        priority=args.priority,
        check=_make_pattern_check(pattern, args.match),
    )
    rule._pattern = pattern
    rule._match_field = args.match

    try:
        fw.add_rule(rule)
    except ValueError as e:
        print(_error(f"Error: {e}"))
        return 1

    # Save rule to storage
    rules_data = storage.load_rules()
    rules_data.append({
        "name": args.name,
        "description": args.description or f"Pattern: {pattern}",
        "action": action.value,
        "priority": args.priority,
        "pattern": pattern,
        "match_field": args.match,
    })
    storage.save_rules(rules_data)
    _save_state(fw, storage)

    print(_success(f"Rule added: {args.name} [{action.value}] pattern='{pattern}' priority={args.priority}"))


def cmd_rule_remove(args):
    """Remove a custom rule."""
    fw, storage = _load_firewall(args.storage_dir)

    if fw.remove_rule(args.name):
        rules_data = [r for r in storage.load_rules() if r["name"] != args.name]
        storage.save_rules(rules_data)
        print(_success(f"Rule removed: {args.name}"))
    else:
        print(_error(f"Cannot remove rule: {args.name} (immutable or not found)"))
        return 1


def cmd_check(args):
    """Check an action against the firewall."""
    fw, storage = _load_firewall(args.storage_dir)

    allowed, token, trust = fw.check(args.agent, args.action, args.intent)

    _save_state(fw, storage)
    storage.append_log(token.to_dict())

    print()
    if allowed:
        print(f"  {_success('ALLOWED')}")
    else:
        print(f"  {_error('BLOCKED')}")

    print(f"  Token:    {token.token_id}")
    print(f"  Rule:     {token.rule_name}")
    print(f"  Reason:   {token.reason}")
    print(f"  Agent:    {token.agent_id}")
    print(f"  Trust:    {trust:.4f} {_trust_bar(trust)}")

    if args.json:
        print()
        print(json.dumps(token.to_dict(), indent=2))
    print()


def cmd_log(args):
    """Show audit log."""
    fw, storage = _load_firewall(args.storage_dir)

    entries = storage.read_log(date=args.date, last_n=args.last)

    if args.agent:
        entries = [e for e in entries if e.get("agent_id") == args.agent]
    if args.blocked:
        entries = [e for e in entries if e.get("action") == "BLOCK"]

    if not entries:
        print(_dim("No log entries found."))
        return

    print()
    print(f"  {_bold('Audit Log')} ({len(entries)} entries):")
    print()
    for e in entries:
        ts = time.strftime("%H:%M:%S", time.localtime(e.get("timestamp", 0)))
        action = _action_colored(e.get("action", "?"))
        agent = e.get("agent_id", "?")
        rule = e.get("rule_name", "?")
        tid = e.get("token_id", "?")[:12]
        print(f"  {_dim(ts)}  {action:6s}  {agent:20s}  {rule:30s}  {_dim(tid)}")
    print()


def cmd_agent_list(args):
    """List registered agents."""
    fw, storage = _load_firewall(args.storage_dir)

    if not fw._agents:
        print(_dim("No agents registered."))
        return

    print()
    print(f"  {_bold('Registered Agents')}:")
    print()
    for name, agent in fw._agents.items():
        state_str = _state_colored(agent.state.value)
        trust = agent.trust_score
        trust_bar = _trust_bar(trust)
        print(f"  {name:20s}  {state_str:10s}  trust={trust:.4f} {trust_bar}")
    print()


def cmd_agent_show(args):
    """Show agent details."""
    fw, storage = _load_firewall(args.storage_dir)

    agent = fw.get_agent(args.name)
    if not agent:
        print(_error(f"Agent not found: {args.name}"))
        return 1

    print()
    print(f"  {_bold('Agent:')} {agent.name}")
    print(f"  State:              {agent.state.value}")
    print(f"  Trust Score:        {agent.trust_score:.4f} {_trust_bar(agent.trust_score)}")
    print()
    print(f"  {_bold('FIR/A Breakdown:')}")
    print(f"    Frequency (F):    {agent.fira.frequency:.4f}  {_dim('activity baseline')}")
    print(f"    Integrity (I):    {agent.fira.integrity:.4f}  {_dim('behavioral consistency')}")
    print(f"    Recency   (R):    {agent.fira.recency:.4f}  {_dim('evidence freshness')}")
    print(f"    Anomaly   (A):    {agent.fira.anomaly:.4f}  {_dim('red flags (lower=better)')}")
    print()
    print(f"  {_bold('Actions:')}")
    print(f"    Total:            {agent.total_actions}")
    print(f"    Allowed:          {agent.allowed_actions}")
    print(f"    Blocked:          {agent.blocked_actions}")
    print(f"    Warned:           {agent.warned_actions}")
    print(f"    Consecutive:      {agent.consecutive_blocks} blocks in a row")
    print()


def cmd_agent_isolate(args):
    """Isolate an agent."""
    fw, storage = _load_firewall(args.storage_dir)

    agent = fw.get_agent(args.name)
    if not agent:
        print(_error(f"Agent not found: {args.name}"))
        return 1

    reason = args.reason or "manual CLI isolation"
    token = fw.isolate(agent, reason=reason)
    _save_state(fw, storage)
    storage.append_log(token.to_dict())

    print(_error(f"Agent isolated: {args.name}"))
    print(f"  Reason: {reason}")
    print(f"  Token:  {token.token_id}")


def cmd_agent_burn(args):
    """Permanently burn an agent. No second chances."""
    fw, storage = _load_firewall(args.storage_dir)

    agent = fw.get_agent(args.name)
    if not agent:
        print(_error(f"Agent not found: {args.name}"))
        return 1

    reason = args.reason or "manual burn via CLI"
    token = fw.burn(agent, reason=reason)
    _save_state(fw, storage)
    storage.append_log(token.to_dict())

    print(_colored(f"Agent BURNED: {args.name}", C.RED + C.BOLD))
    print(f"  Reason:  {reason}")
    print(f"  Trust:   0.0000 (irrecoverable)")
    print(f"  Token:   {token.token_id}")
    print(f"  Status:  {_colored('BURNED — permanently blacklisted', C.RED + C.BOLD)}")


def cmd_agent_reinstate(args):
    """Reinstate an isolated agent."""
    fw, storage = _load_firewall(args.storage_dir)

    agent = fw.get_agent(args.name)
    if not agent:
        print(_error(f"Agent not found: {args.name}"))
        return 1

    if agent.is_burned:
        print(_colored(f"DENIED: Agent {args.name} is BURNED — reinstatement not possible", C.RED + C.BOLD))
        return 1

    token = fw.reinstate(agent)
    _save_state(fw, storage)
    storage.append_log(token.to_dict())

    print(_success(f"Agent reinstated: {args.name}"))
    print(f"  New trust: {agent.trust_score:.4f} (degraded)")
    print(f"  Token:     {token.token_id}")


def cmd_audit_summary(args):
    """Show audit compliance summary."""
    fw, storage = _load_firewall(args.storage_dir)
    comp = fw.compliance

    if not comp:
        print(_dim("Compliance engine not enabled."))
        return

    print()
    print(f"  {_bold('SNAFT EU AI Act Compliance Summary')}")
    print(f"  {_dim('Regulation (EU) 2024/1689 — Enforcement: 2 August 2026')}")
    print()
    print(f"  Risk level:     {_warn(comp.risk_level.value)}")
    print(f"  Retention:      {comp.retention_days} days {_dim('(Art. 26 minimum: 180)')}")
    print(f"  Audit records:  {comp.record_count}")
    print()

    if comp.record_count == 0:
        print(f"  {_dim('No audit records yet. Records are generated automatically on every evaluate().')}")
        print()
        return

    # Summary stats
    records = comp.get_records()
    categories = {}
    for r in records:
        categories[r.category] = categories.get(r.category, 0) + 1

    print(f"  {_bold('Records by category:')}")
    for cat, count in sorted(categories.items()):
        print(f"    {cat:20s}  {count}")
    print()

    # Show applicable articles
    articles_seen = set()
    for r in records:
        for a in r.articles:
            articles_seen.add(a)

    if articles_seen:
        print(f"  {_bold('EU AI Act articles covered:')}")
        for a in sorted(articles_seen):
            print(f"    {_success('*')} {a}")
        print()


def cmd_audit_export(args):
    """Export compliance audit records."""
    fw, storage = _load_firewall(args.storage_dir)
    comp = fw.compliance

    if not comp:
        print(_error("Compliance engine not enabled."), file=sys.stderr)
        return 1

    if comp.record_count == 0:
        print(_dim("No audit records to export."), file=sys.stderr)
        return 1

    if args.format == "csv":
        output = comp.export_csv_header() + "\n"
        output += "\n".join(comp.export_csv_rows())
    else:
        output = comp.export_json()

    if args.output:
        with open(args.output, "w") as f:
            f.write(output)
        print(_success(f"Exported {comp.record_count} audit records to {args.output}"))
    else:
        print(output)


def cmd_audit_verify(args):
    """Verify audit record integrity."""
    fw, storage = _load_firewall(args.storage_dir)
    comp = fw.compliance

    if not comp:
        print(_error("Compliance engine not enabled."), file=sys.stderr)
        return 1

    records = comp.get_records()
    if not records:
        print(_dim("No audit records to verify."))
        return

    passed = 0
    failed = 0
    for r in records:
        if comp.verify_record(r):
            passed += 1
        else:
            failed += 1
            print(_error(f"  TAMPERED: {r.record_id} ({r.timestamp_iso})"))

    print()
    if failed == 0:
        print(_success(f"  All {passed} audit records verified — integrity intact"))
    else:
        print(_error(f"  {failed} tampered records detected out of {passed + failed}"))
    print()


def cmd_version(args):
    """Show version info."""
    from .kernel import TrustKernel
    k = TrustKernel()
    print(f"snaft {__version__}")
    print(f"kernel: {k.backend}")
    print("Semantic Network-Aware Firewall for Trust")
    print("Not a guardrail. An immune system.")


def cmd_reset(args):
    """Reset all state."""
    if not args.confirm:
        print(_error("This will wipe all SNAFT state (rules, agents, logs)."))
        print(f"Run with {_bold('--confirm')} to proceed.")
        return 1

    storage = Storage(storage_dir=args.storage_dir)
    storage.wipe(confirm=True)
    print(_warn("All SNAFT state has been reset."))


# =============================================================================
# HELPERS
# =============================================================================

def _trust_bar(score: float, width: int = 20) -> str:
    """Visual trust bar."""
    filled = int(score * width)
    empty = width - filled
    if score >= 0.8:
        color = C.GREEN
    elif score >= 0.5:
        color = C.YELLOW
    elif score >= 0.2:
        color = C.RED
    else:
        color = C.RED + C.BOLD

    if sys.stdout.isatty():
        return f"{color}{'█' * filled}{'░' * empty}{C.RESET}"
    else:
        return f"[{'#' * filled}{'.' * empty}]"


def _state_colored(state: str) -> str:
    """Color-code an agent state string."""
    if state == "active":
        return _success(state)
    elif state == "degraded":
        return _warn(state)
    elif state == "isolated":
        return _error(state)
    elif state == "burned":
        return _colored(f"BURNED", C.RED + C.BOLD)
    return _dim(state)


def _action_colored(action: str) -> str:
    """Color-code an action string."""
    if action == "ALLOW":
        return _success(action)
    elif action == "BLOCK":
        return _error(action)
    elif action == "WARN":
        return _warn(action)
    elif action == "ISOLATE":
        return _colored(action, C.MAGENTA)
    return action


# =============================================================================
# ARGUMENT PARSER
# =============================================================================

def build_parser() -> argparse.ArgumentParser:
    # Parent parser with shared --storage-dir argument
    parent = argparse.ArgumentParser(add_help=False)
    parent.add_argument("--storage-dir", dest="storage_dir", default=None,
                        help="Override storage directory (default: ~/.snaft)")

    parser = argparse.ArgumentParser(
        prog="snaft",
        description="SNAFT — Semantic Network-Aware Firewall for Trust",
        epilog="Not a guardrail. An immune system.",
    )

    sub = parser.add_subparsers(dest="command", help="Available commands")

    # status
    sub.add_parser("status", help="Show firewall status", parents=[parent])

    # enable / disable
    sub.add_parser("enable", help="Enable the firewall", parents=[parent])
    sub.add_parser("disable", help="Disable the firewall", parents=[parent])

    # rule
    rule_parser = sub.add_parser("rule", help="Manage firewall rules")
    rule_sub = rule_parser.add_subparsers(dest="rule_command")

    rule_sub.add_parser("list", help="List all rules", parents=[parent])

    rule_add = rule_sub.add_parser("add", help="Add a custom rule", parents=[parent])
    rule_add.add_argument("name", help="Rule name")
    rule_add.add_argument("action", choices=["ALLOW", "BLOCK", "WARN", "allow", "block", "warn"],
                          help="Action when rule matches")
    rule_add.add_argument("pattern", help="Regex pattern to match")
    rule_add.add_argument("--priority", type=int, default=100, help="Priority (lower = checked first)")
    rule_add.add_argument("--description", "-d", default=None, help="Rule description")
    rule_add.add_argument("--match", choices=["intent", "action", "both"], default="intent",
                          help="What to match the pattern against (default: intent)")

    rule_rm = rule_sub.add_parser("remove", help="Remove a custom rule", parents=[parent])
    rule_rm.add_argument("name", help="Rule name to remove")

    # check
    check_parser = sub.add_parser("check", help="Check an action against the firewall", parents=[parent])
    check_parser.add_argument("agent", help="Agent name")
    check_parser.add_argument("action", help="Action to check")
    check_parser.add_argument("intent", help="Intent behind the action")
    check_parser.add_argument("--json", action="store_true", help="Output full token as JSON")

    # log
    log_parser = sub.add_parser("log", help="Show audit log", parents=[parent])
    log_parser.add_argument("--last", type=int, default=20, help="Number of entries (default: 20)")
    log_parser.add_argument("--agent", default=None, help="Filter by agent")
    log_parser.add_argument("--blocked", action="store_true", help="Show only blocked actions")
    log_parser.add_argument("--date", default=None, help="Log date (YYYY-MM-DD, default: today)")

    # agent
    agent_parser = sub.add_parser("agent", help="Manage agents")
    agent_sub = agent_parser.add_subparsers(dest="agent_command")

    agent_sub.add_parser("list", help="List registered agents", parents=[parent])

    agent_show = agent_sub.add_parser("show", help="Show agent details", parents=[parent])
    agent_show.add_argument("name", help="Agent name")

    agent_iso = agent_sub.add_parser("isolate", help="Isolate an agent", parents=[parent])
    agent_iso.add_argument("name", help="Agent name")
    agent_iso.add_argument("reason", nargs="?", default=None, help="Isolation reason")

    agent_burn = agent_sub.add_parser("burn", help="Permanently burn an agent (irrecoverable)", parents=[parent])
    agent_burn.add_argument("name", help="Agent name")
    agent_burn.add_argument("reason", nargs="?", default=None, help="Burn reason")

    agent_re = agent_sub.add_parser("reinstate", help="Reinstate an isolated agent", parents=[parent])
    agent_re.add_argument("name", help="Agent name")

    # audit (EU AI Act compliance)
    audit_parser = sub.add_parser("audit", help="EU AI Act compliance audit")
    audit_sub = audit_parser.add_subparsers(dest="audit_command")

    audit_sub.add_parser("summary", help="Show compliance summary", parents=[parent])

    audit_export = audit_sub.add_parser("export", help="Export audit records", parents=[parent])
    audit_export.add_argument("--format", choices=["json", "csv"], default="json",
                              help="Export format (default: json)")
    audit_export.add_argument("--output", "-o", default=None,
                              help="Output file (default: stdout)")

    audit_sub.add_parser("verify", help="Verify audit record integrity", parents=[parent])

    # version
    sub.add_parser("version", help="Show version info")

    # reset
    reset_parser = sub.add_parser("reset", help="Reset all state", parents=[parent])
    reset_parser.add_argument("--confirm", action="store_true", help="Confirm state wipe")

    return parser


# =============================================================================
# MAIN
# =============================================================================

def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 0

    # Ensure storage_dir attr exists (some subcommands like 'version' don't have it)
    if not hasattr(args, "storage_dir"):
        args.storage_dir = None

    commands = {
        "status": cmd_status,
        "enable": cmd_enable,
        "disable": cmd_disable,
        "check": cmd_check,
        "log": cmd_log,
        "version": cmd_version,
        "reset": cmd_reset,
    }

    # Direct commands
    if args.command in commands:
        result = commands[args.command](args)
        return result or 0

    # Rule subcommands
    if args.command == "rule":
        if args.rule_command == "list":
            return cmd_rule_list(args) or 0
        elif args.rule_command == "add":
            return cmd_rule_add(args) or 0
        elif args.rule_command == "remove":
            return cmd_rule_remove(args) or 0
        else:
            print("Usage: snaft rule {list|add|remove}")
            return 1

    # Agent subcommands
    if args.command == "agent":
        if args.agent_command == "list":
            return cmd_agent_list(args) or 0
        elif args.agent_command == "show":
            return cmd_agent_show(args) or 0
        elif args.agent_command == "isolate":
            return cmd_agent_isolate(args) or 0
        elif args.agent_command == "burn":
            return cmd_agent_burn(args) or 0
        elif args.agent_command == "reinstate":
            return cmd_agent_reinstate(args) or 0
        else:
            print("Usage: snaft agent {list|show|isolate|reinstate}")
            return 1

    # Audit subcommands (EU AI Act compliance)
    if args.command == "audit":
        if args.audit_command == "summary":
            return cmd_audit_summary(args) or 0
        elif args.audit_command == "export":
            return cmd_audit_export(args) or 0
        elif args.audit_command == "verify":
            return cmd_audit_verify(args) or 0
        else:
            print("Usage: snaft audit {summary|export|verify}")
            return 1

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
