"""
Alert Detection System
"""

import uuid
from typing import List, Dict, Any


def run_detections(entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Run detection rules on parsed entries"""
    alerts = []
    seen_ids = set()

    for entry in entries:
        source_ip = entry.get("source", {}).get("ip") or "unknown"
        target_user = entry.get("user", {}).get("name") or "unknown"
        entry_id = entry.get("id", str(uuid.uuid4()))

        # Skip duplicates
        if entry_id in seen_ids:
            continue
        seen_ids.add(entry_id)

        # Check for attack type first (higher priority)
        attack_type = entry.get("attackType")
        if attack_type and isinstance(attack_type, str):
            confidence = entry.get("attackConfidence", 0)
            confidence_level = (
                "high"
                if confidence >= 0.8
                else "medium"
                if confidence >= 0.5
                else "low"
            )

            alerts.append(
                {
                    "id": entry_id,
                    "type": attack_type,
                    "severity": "high",
                    "confidence": confidence_level,
                    "title": f"{attack_type.replace('_', ' ').title()} Attack Detected",
                    "description": f"Attack detected: {attack_type} (confidence: {confidence:.0%})",
                    "timestamp": entry.get("timestamp") or "",
                    "sourceIps": [source_ip] if source_ip != "unknown" else [],
                    "targetUsers": [target_user] if target_user != "unknown" else [],
                    "relatedEvents": [entry_id],
                    "metadata": {"entry": entry},
                }
            )
        # Check for failed logins (only if no attack type detected)
        elif entry.get("outcome") == "failure":
            alerts.append(
                {
                    "id": entry_id,
                    "type": "bruteforce",
                    "severity": "medium",
                    "confidence": "medium",
                    "title": "Failed Login Attempt",
                    "description": f"Failed login attempt from {source_ip}",
                    "timestamp": entry.get("timestamp") or "",
                    "sourceIps": [source_ip] if source_ip != "unknown" else [],
                    "targetUsers": [target_user] if target_user != "unknown" else [],
                    "relatedEvents": [entry_id],
                    "metadata": {"entry": entry},
                }
            )

    return alerts


def generate_stats(entries: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Generate statistics from entries"""
    by_severity = {}
    by_outcome = {}
    by_type = {}
    source_ips = set()
    users = set()

    for entry in entries:
        # By severity
        severity = entry.get("severity", "unknown")
        by_severity[severity] = by_severity.get(severity, 0) + 1

        # By outcome
        outcome = entry.get("outcome", "unknown")
        by_outcome[outcome] = by_outcome.get(outcome, 0) + 1

        # By type
        log_type = entry.get("logType", "unknown")
        by_type[log_type] = by_type.get(log_type, 0) + 1

        # Source IPs
        if entry.get("source", {}).get("ip"):
            source_ips.add(entry["source"]["ip"])

        # Users
        if entry.get("user", {}).get("name"):
            users.add(entry["user"]["name"])

    return {
        "bySeverity": by_severity,
        "byOutcome": by_outcome,
        "byType": by_type,
        "uniqueSources": len(source_ips),
        "uniqueUsers": len(users),
    }
