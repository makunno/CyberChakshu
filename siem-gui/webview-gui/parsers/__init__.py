"""Parser Registry - Combines all parsers and provides detection/parsing functionality"""

import re
from collections import Counter
from typing import List, Tuple, Optional
from .base import Parser
from .types import LogType, LogEntry, Severity

# Get all parsers from modules (lazy loading)
def _get_all_parsers() -> List[Parser]:
    """Combine all parsers into a single registry"""
    all_parsers = []

    try:
        from . import auth as auth_parsers
        all_parsers.extend(getattr(auth_parsers, 'PARSERS', []))
    except ImportError:
        pass

    try:
        from . import firewall as firewall_parsers
        all_parsers.extend(getattr(firewall_parsers, 'PARSERS', []))
    except ImportError:
        pass

    try:
        from . import mail as mail_parsers
        all_parsers.extend(getattr(mail_parsers, 'PARSERS', []))
    except ImportError:
        pass

    try:
        from . import database as database_parsers
        all_parsers.extend(getattr(database_parsers, 'PARSERS', []))
    except ImportError:
        pass

    try:
        from . import webserver as webserver_parsers
        all_parsers.extend(getattr(webserver_parsers, 'PARSERS', []))
    except ImportError:
        pass

    try:
        from . import system as system_parsers
        all_parsers.extend(getattr(system_parsers, 'PARSERS', []))
    except ImportError:
        pass

    return all_parsers


ALL_PARSERS = _get_all_parsers()

# Dynamic parser (fallback)
try:
    from . import dynamic as dynamic_parser
    RAW_PARSER = dynamic_parser.DynamicParser()
except ImportError:
    # Fallback if dynamic parser fails
    class FallbackParser(Parser):
        def __init__(self):
            super().__init__("Fallback", LogType.UNKNOWN)

        def detect(self, line: str) -> bool:
            return True

        def parse(self, line: str) -> LogEntry:
            return LogEntry(line, log_type=self.log_type, severity=Severity.INFO, message=line)

    RAW_PARSER = FallbackParser()


def detect_log_type(lines: List[str], sample_size: int = 50) -> LogType:
    """Detect log type by sampling lines"""
    scores: dict = {}

    # Initialize scores
    for parser in ALL_PARSERS:
        scores[parser.log_type] = 0
    scores[LogType.UNKNOWN] = 0

    # Sample lines for detection
    samples_to_check = lines[:sample_size]

    for line in samples_to_check:
        trimmed = line.strip()
        if not trimmed or trimmed.startswith('#'):
            continue

        matched = False
        for parser in ALL_PARSERS:
            if parser.detect(trimmed):
                scores[parser.log_type] = scores.get(parser.log_type, 0) + 1
                matched = True
                break

        if not matched:
            scores[LogType.UNKNOWN] = scores.get(LogType.UNKNOWN, 0) + 1

    # Find highest scoring log type
    best_type = LogType.UNKNOWN
    best_score = 0

    for log_type, score in scores.items():
        if score > best_score:
            best_score = score
            best_type = log_type

    # If too few matches, return unknown
    if best_score < 3:
        return LogType.UNKNOWN

    return best_type


def get_parser(log_type: LogType) -> Parser:
    """Get parser for a specific log type"""
    if log_type in [LogType.RAW, LogType.UNKNOWN]:
        return RAW_PARSER
    for parser in ALL_PARSERS:
        if parser.log_type == log_type:
            return parser
    return RAW_PARSER


def auto_parse_line(line: str) -> LogEntry:
    """Auto-detect and parse a single line"""
    trimmed = line.strip()
    if not trimmed:
        return RAW_PARSER.parse(line)

    for parser in ALL_PARSERS:
        if parser.detect(trimmed):
            result = parser.parse(trimmed)
            if result:
                return result

    return RAW_PARSER.parse(line)


def auto_parse(content: str) -> dict:
    """Auto-detect log type and parse all lines"""
    lines = [l for l in content.split('\n') if l.strip()]
    detected_type = detect_log_type(lines)

    entries = []
    parsed_count = 0
    failed_count = 0

    if detected_type in [LogType.UNKNOWN, LogType.RAW]:
        # Auto-parse each line individually
        for line in lines:
            result = auto_parse_line(line)
            if result.log_type not in [LogType.RAW, LogType.UNKNOWN]:
                parsed_count += 1
            else:
                failed_count += 1
            entries.append(result)
    else:
        # Use specific parser
        parser = get_parser(detected_type)
        for line in lines:
            trimmed = line.strip()
            if not trimmed or trimmed.startswith('#'):
                continue

            result = parser.parse(trimmed)
            if result:
                entries.append(result)
                parsed_count += 1
            else:
                # Fallback to auto-parsing
                auto_parsed = auto_parse_line(trimmed)
                entries.append(auto_parsed)
                if auto_parsed.log_type not in [LogType.RAW, LogType.UNKNOWN]:
                    parsed_count += 1
                else:
                    failed_count += 1

    return {
        'detectedType': detected_type.value,
        'entries': [e.to_dict() for e in entries],
        'stats': {
            'totalLines': len(lines),
            'parsedLines': parsed_count,
            'failedLines': failed_count,
        }
    }
