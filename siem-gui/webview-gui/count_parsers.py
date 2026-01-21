"""Count available parsers"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from parsers import ALL_PARSERS

print(f"Total parsers loaded: {len(ALL_PARSERS)}")

parser_types = {}
for parser in ALL_PARSERS:
    parser_type = parser.__class__.__module__.split('.')[-1]
    if parser_type not in parser_types:
        parser_types[parser_type] = []
    parser_types[parser_type].append(parser.name)

print("\nParsers by category:")
for category, parsers in parser_types.items():
    print(f"  {category}: {len(parsers)} parsers")
    for parser in parsers[:3]:  # Show first 3
        print(f"    - {parser}")
    if len(parsers) > 3:
        print(f"    ... and {len(parsers) - 3} more")

print(f"\nTotal unique parser types: {len(set(p.log_type.value for p in ALL_PARSERS))}")