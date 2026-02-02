"""Parser Registry - Combines all parsers and provides detection/parsing functionality
MIGRATED: Now uses ISEA-style LogDetector for detection"""

import re
from collections import Counter
from typing import List, Tuple, Optional
from .base import Parser
from .types import LogType, LogEntry, Severity

# Import ISEA-style detection and parsing
from .log_detector import LogDetector
from .log_parsers import LogParsers
from .legacy_parser import parse_with_legacy_parser

# Import type mapping and use alias for LogType to avoid conflicts
from . import type_mapping
LocalLogType = type_mapping.LogType
TYPE_MAPPING = type_mapping.TYPE_MAPPING

# Import dynamic parser utilities (fallback)
try:
    from . import dynamic as dynamic_parser
    RAW_PARSER = dynamic_parser.DynamicParser()
except ImportError:
    # Fallback if dynamic parser fails
    class FallbackParser(Parser):
        def __init__(self):
            super().__init__("Fallback", LocalLogType.UNKNOWN)

        def detect(self, line: str) -> bool:
            return True

        def parse(self, line: str) -> LogEntry:
            return LogEntry(line, log_type=self.log_type, severity=Severity.INFO, message=line)

    RAW_PARSER = FallbackParser()


def detect_log_type(content: str) -> LocalLogType:
    """Detect log type using ISEA-style LogDetector"""
    iseat_type = LogDetector.detect(content)
    return TYPE_MAPPING.get(iseat_type, LocalLogType.UNKNOWN)


def get_parser(log_type: LocalLogType) -> Parser:
    """Get parser for a specific log type"""
    if log_type in [LocalLogType.UNKNOWN, LocalLogType.UNKNOWN]:
        return RAW_PARSER
    
    # Get old-style parsers from modules for backward compatibility
    try:
        from . import auth as auth_module
        parsers = getattr(auth_module, 'PARSERS', [])
        for p in parsers:
            if p.log_type == log_type:
                return p
    except ImportError:
        pass
    
    try:
        from . import firewall as firewall_module
        parsers = getattr(firewall_module, 'PARSERS', [])
        for p in parsers:
            if p.log_type == log_type:
                return p
    except ImportError:
        pass
    
    try:
        from . import mail as mail_module
        parsers = getattr(mail_module, 'PARSERS', [])
        for p in parsers:
            if p.log_type == log_type:
                return p
    except ImportError:
        pass
    
    try:
        from . import database as database_module
        parsers = getattr(database_module, 'PARSERS', [])
        for p in parsers:
            if p.log_type == log_type:
                return p
    except ImportError:
        pass
    
    try:
        from . import webserver as webserver_module
        parsers = getattr(webserver_module, 'PARSERS', [])
        for p in parsers:
            if p.log_type == log_type:
                return p
    except ImportError:
        pass
    
    try:
        from . import system as system_module
        parsers = getattr(system_module, 'PARSERS', [])
        for p in parsers:
            if p.log_type == log_type:
                return p
    except ImportError:
        pass
    
    return RAW_PARSER


def auto_parse_line(line: str) -> LogEntry:
    """Auto-detect and parse a single line"""
    trimmed = line.strip()
    if not trimmed:
        return RAW_PARSER.parse(line)

    # Try ISEA-style parsing with LogDetector
    iseat_type = LogDetector.detect(line)
    if iseat_type != 'Custom / Raw':
        parsed = parse_with_legacy_parser(iseat_type, trimmed)
        if parsed:
            return parsed

    # Fallback to old parsers for backward compatibility
    try:
        from . import auth as auth_module
        parsers = getattr(auth_module, 'PARSERS', [])
        for p in parsers:
            if p.detect(trimmed):
                result = p.parse(trimmed)
                if result:
                    return result
    except ImportError:
        pass

    try:
        from . import firewall as firewall_module
        parsers = getattr(firewall_module, 'PARSERS', [])
        for p in parsers:
            if p.detect(trimmed):
                result = p.parse(trimmed)
                if result:
                    return result
    except ImportError:
        pass

    try:
        from . import mail as mail_module
        parsers = getattr(mail_module, 'PARSERS', [])
        for p in parsers:
            if p.detect(trimmed):
                result = p.parse(trimmed)
                if result:
                    return result
    except ImportError:
        pass

    try:
        from . import database as database_module
        parsers = getattr(database_module, 'PARSERS', [])
        for p in parsers:
            if p.detect(trimmed):
                result = p.parse(trimmed)
                if result:
                    return result
    except ImportError:
        pass

    try:
        from . import webserver as webserver_module
        parsers = getattr(webserver_module, 'PARSERS', [])
        for p in parsers:
            if p.detect(trimmed):
                result = p.parse(trimmed)
                if result:
                    return result
    except ImportError:
        pass

    try:
        from . import system as system_module
        parsers = getattr(system_module, 'PARSERS', [])
        for p in parsers:
            if p.detect(trimmed):
                result = p.parse(trimmed)
                if result:
                    return result
    except ImportError:
        pass

    return RAW_PARSER.parse(line)


def auto_parse(content: str) -> dict:
    """Auto-detect log type and parse all lines
MIGRATED: Now uses ISEA-style detection and parsing"""
    lines = [l for l in content.split('\n') if l.strip()]
    detected_type = detect_log_type(content)

    entries = []
    parsed_count = 0
    failed_count = 0

    if detected_type in [LocalLogType.UNKNOWN, LocalLogType.UNKNOWN]:
        # Auto-parse each line individually using ISEA-style parsers
        iseat_type = detected_type.value if detected_type != LocalLogType.UNKNOWN else 'Custom / Raw'
        for line in lines:
            trimmed = line.strip()
            if not trimmed or trimmed.startswith('#'):
                continue
            
            parsed = parse_with_legacy_parser(iseat_type, trimmed)
            if parsed:
                entries.append(parsed)
                parsed_count += 1
            else:
                # Fallback to raw parsing
                result = auto_parse_line(trimmed)
                entries.append(result)
                if result.log_type != LocalLogType.UNKNOWN and result.log_type != LocalLogType.UNKNOWN:
                    parsed_count += 1
                else:
                    failed_count += 1
    else:
        # Use ISEA-style parser for this log type
        iseat_type = detected_type.value if detected_type != LocalLogType.UNKNOWN else 'Custom / Raw'
        for line in lines:
            trimmed = line.strip()
            if not trimmed or trimmed.startswith('#'):
                continue
            
            parsed = parse_with_legacy_parser(iseat_type, trimmed)
            if parsed:
                entries.append(parsed)
                parsed_count += 1
            else:
                # Fallback to auto-parsing
                result = auto_parse_line(trimmed)
                entries.append(result)
                if result.log_type != LocalLogType.UNKNOWN and result.log_type != LocalLogType.UNKNOWN:
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
        },
    }
