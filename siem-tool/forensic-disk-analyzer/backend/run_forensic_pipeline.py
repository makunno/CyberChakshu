#!/usr/bin/env python3
"""
Unified Disk Forensic Pipeline
Coordinates extraction, binary parsing, layered correlation, and AI reporting.
"""

import os
import sys
import json
import argparse
import re
import shutil
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any

# Add parent directory to path to import our modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../imageProcessor")
)

from forensic_extractor import ForensicExtractor
from layered_correlation_engine import run_layered_analysis_for_all_partitions
from hardcoded_timestomp_detector import run_hardcoded_detection
from hardcoded_report_generator import generate_reports
from ai_preprocessor import ForensicPreprocessor
from ai_forensic_analyzer import AIForensicAnalyzer
from advanced_antiforensic_detector import (
    AdvancedAntiForensicDetector,
    create_detector_from_parsers,
)
from ntfs_forensics.mft_parser import MFTParser
from ntfs_forensics.usn_parser import USNJournalParser
from ntfs_forensics.logfile_parser import LogFileParser
from ntfs_forensics.volume_parser import VolumeInfoParser

try:
    from log_extractor import LogExtractor

    HAS_LOG_EXTRACTOR = True
except ImportError:
    HAS_LOG_EXTRACTOR = False


def run_pipeline(
    image_path,
    output_dir,
    api_key=None,
    skip_extraction=False,
    ollama_url=None,
    model=None,
):
    print("=" * 80)
    print("           FREEKHANA UNIFIED DISK FORENSIC PIPELINE (v2)")
    print("=" * 80)

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    # Step 1: Extraction
    if not skip_extraction:
        print(f"\n[*] STEP 1: Extracting artifacts from {image_path}...")
        extractor = ForensicExtractor(image_path, output_dir)
        # We use --all equivalent
        summary = extractor.extract_everything()
        print(f"    Extracted artifacts from {len(summary['partitions'])} partitions.")

        # Copy all logs to forensic_output directory
        print("\n[*] STEP 1b: Copying logs to forensic output...")
        logs_source = Path(output_dir) / "logs"
        logs_dest = output_path / "logs"

        if logs_source.exists():
            if logs_dest.exists():
                shutil.rmtree(logs_dest)
            shutil.copytree(logs_source, logs_dest)

            # Count evtx JSON files
            evtx_json_count = len(list(logs_dest.glob("**/*.evtx.json")))
            print(f"    Copied {evtx_json_count} EVTX log files (as JSON)")
        else:
            print("    No logs directory found to copy")

        # Extract EVTX logs as JSON using LogExtractor
        if HAS_LOG_EXTRACTOR and image_path:
            print("\n[*] STEP 1c: Extracting EVTX logs as JSON...")
            try:
                log_extractor = LogExtractor(
                    image_path, output_dir, evtx_format="json", size_limit_mb=100
                )
                log_summary = log_extractor.extract_all()
                evtx_count = (
                    log_summary.by_type.get("evtx", 0)
                    if hasattr(log_summary, "by_type")
                    else 0
                )
                print(f"    Extracted {evtx_count} EVTX log files as JSON")

                # Copy the newly extracted logs
                logs_source = Path(output_dir) / "logs"
                if logs_source.exists():
                    if logs_dest.exists():
                        shutil.rmtree(logs_dest)
                    shutil.copytree(logs_source, logs_dest)
                    evtx_json_count = len(list(logs_dest.glob("**/*.evtx.json")))
                    print(f"    Total EVTX JSON files in output: {evtx_json_count}")
            except Exception as e:
                print(f"    Warning: Failed to extract EVTX logs: {e}")
    else:
        print(f"\n[*] STEP 1: Using existing artifacts in {output_dir}")

        # Copy all logs to forensic_output directory
        print("\n[*] STEP 1b: Copying logs to forensic output...")
        logs_source = Path(output_dir) / "logs"
        logs_dest = output_path / "logs"

        if logs_source.exists():
            if logs_dest.exists():
                shutil.rmtree(logs_dest)
            shutil.copytree(logs_source, logs_dest)

            # Count evtx JSON files
            evtx_json_count = len(list(logs_dest.glob("**/*.evtx.json")))
            print(f"    Copied {evtx_json_count} EVTX log files (as JSON)")
        else:
            print("    No logs directory found to copy")

    # Step 2: Layered Correlation Analysis (The "Smart" part)
    print(
        "\n[*] STEP 2: Running Layered Correlation Engine (MFT/USN/LogFile/Artifacts)..."
    )
    layered_results = run_layered_analysis_for_all_partitions(output_dir)

    # Consolidate findings from all partitions
    if "findings" not in layered_results or not layered_results["findings"]:
        all_f = []
        for part in layered_results.get("partition_results", []):
            res = part.get("result", {})
            all_f.extend(res.get("findings", []))
        layered_results["findings"] = all_f

    # Save layered results
    layered_json = output_path / "layered_analysis_results.json"
    with open(layered_json, "w") as f:
        json.dump(layered_results, f, indent=2, default=str)

    print(
        f"    Analyzed {layered_results.get('analysis_summary', {}).get('total_files_analyzed', 0)} files."
    )
    print(
        f"    Detected {layered_results.get('analysis_summary', {}).get('suspicious_files', 0)} suspicious files."
    )

    # Step 2b: Hardcoded Timestomping Detection
    print("\n[*] STEP 2b: Running Hardcoded Timestomping Detection...")
    hardcoded_results = run_hardcoded_detection(output_dir)

    # Generate Hardcoded Reports (TXT, JSON, CSV, HTML)
    print("\n[*] STEP 2c: Generating Hardcoded Forensic Reports...")
    reports = generate_reports(output_dir, hardcoded_results)
    print(f"    Text Report: {reports['text']}")
    print(f"    JSON Report: {reports['json']}")
    print(f"    CSV Report:  {reports['csv']}")
    print(f"    HTML Report: {reports['html']}")

    # Step 2d: Advanced Anti-Forensic Detection (11 forensic checks)
    print("\n[*] STEP 2d: Running Advanced Anti-Forensic Detection (11 checks)...")
    advanced_results = run_advanced_antiforensic_analysis(output_dir)

    # Save advanced results
    advanced_json = output_path / "advanced_antiforensic_results.json"
    with open(advanced_json, "w") as f:
        json.dump(advanced_results, f, indent=2, default=str)

    print(f"    Files analyzed: {advanced_results['summary']['total_files_analyzed']}")
    print(
        f"    Timestomped files detected: {advanced_results['summary']['timestomped_files']}"
    )
    print(f"    High severity: {advanced_results['summary']['high_severity_count']}")
    print(
        f"    Critical severity: {advanced_results['summary']['critical_severity_count']}"
    )

    # Copied Files Detection (from possiblyCopied.txt)
    print("\n[*] STEP 2e: Detecting possibly copied files...")
    copied_files = []
    copied_path = Path(output_dir) / "possiblyCopied.txt"
    if copied_path.exists():
        content = copied_path.read_text(errors="ignore")
        for line in content.split("\n"):
            if (
                any(line.startswith(x) for x in ["=", "Total", "Filename"])
                or not line.strip()
            ):
                continue
            dates = re.findall(r"\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}", line)
            if len(dates) >= 2:
                idx = line.find(dates[0])
                if idx >= 0:
                    filename = line[:idx].strip()
                    if filename and len(filename) > 1:
                        copied_files.append(
                            {
                                "filename": filename,
                                "created": dates[0],
                                "modified": dates[1],
                                "reason": "Modified < Created (possibly external source)",
                            }
                        )
    print(f"    Detected {len(copied_files)} possibly copied files.")

    # Step 3: AI Preprocessing
    print("\n[*] STEP 3: Preprocessing for AI Analysis...")
    preprocessor = ForensicPreprocessor(output_dir)
    preprocessed_data = preprocessor.run_full_preprocessing()

    # Step 4: AI Analysis
    # Use OpenRouter API with model from environment or default
    model = model or os.environ.get("OPENROUTER_MODEL", "google/gemini-2.0-flash-001")

    if api_key:
        print(f"\n[*] STEP 4: Running AI Forensic Analyzer (Model: {model})...")
        analyzer = AIForensicAnalyzer(output_dir, api_key, model)

        # We ensure preprocessed data is fresh and has layered findings
        preprocessed_data["layered_findings"] = layered_results
        preprocessed_data["copied_files"] = copied_files

        ai_results = analyzer.analyze(preprocessed_data)

        # Save AI results
        ai_json = output_path / "ai_analysis_results.json"
        with open(ai_json, "w") as f:
            json.dump(ai_results, f, indent=2, default=str)

        # Generate HTML Report
        print("\n[*] STEP 5: Generating 'Live Tampering' Forensic Report...")
        analyzer.generate_html_report(ai_results)
        print(f"    Report generated: {output_path}/live_tampering_report.html")
    else:
        print("\n[!] STEP 4: Skipping AI Analysis (No AI config provided)")

    print("\n" + "=" * 80)
    print("           PIPELINE EXECUTION COMPLETE")
    print("=" * 80)

    # Return all results for the caller
    return {
        "layered_analysis": layered_results,
        "timestomping": hardcoded_results,
        "advanced_analysis": advanced_results,
        "copied_files": {"files": copied_files, "count": len(copied_files)},
        "ai_analysis": ai_results if "ai_results" in locals() else None,
    }


def run_advanced_antiforensic_analysis(output_dir: str) -> Dict:
    """Run the advanced 11-check anti-forensic analysis on extracted artifacts."""
    from pathlib import Path

    output_path = Path(output_dir)
    results = {
        "analysis_type": "Advanced Anti-Forensic Detection (11 checks)",
        "checks_implemented": [
            "1. $SI vs $FN Drift Analysis",
            "2. USN Temporal Forward Check",
            "3. $LogFile LSN Monotonicity",
            "4. Volume Creation Time Check",
            "5. OS Install Time Check",
            "6. Boot-Time Boundary Violations",
            "7. Clock Rollback Detection",
            "8. MFT Record Sequence Analysis",
            "9. Timestamp Entropy Analysis",
            "10. Microsecond/Nanosecond Patterns",
            "11. Shadow Copy Differential Reconstruction",
        ],
        "file_results": [],
        "batch_patterns": [],
        "clock_rollbacks": [],
        "summary": {
            "total_files_analyzed": 0,
            "timestomped_files": 0,
            "high_severity_count": 0,
            "critical_severity_count": 0,
            "medium_severity_count": 0,
        },
    }

    partition_dirs = list(output_path.glob("partition_*"))
    if not partition_dirs:
        partition_dirs = [output_path]

    filesystem_type = "unknown"
    extraction_summary_file = output_path / "extraction_summary.json"
    if extraction_summary_file.exists():
        with open(extraction_summary_file, "r") as f:
            summary = json.load(f)
            if summary.get("partitions"):
                part_desc = summary["partitions"][0].get("desc", "")
                if "FAT" in part_desc.upper():
                    filesystem_type = "FAT"
                elif "NTFS" in part_desc.upper():
                    filesystem_type = "NTFS"

    results["filesystem_type"] = filesystem_type

    if filesystem_type != "NTFS":
        results["note"] = (
            f"Advanced anti-forensic detection requires NTFS filesystem. Found {filesystem_type}."
        )
        results["file_results"] = []
        results["summary"]["note"] = (
            f"Filesystem is {filesystem_type} - MFT analysis not applicable"
        )
        return results

    for part_dir in partition_dirs:
        mft_file = part_dir / "mft_partition_0.bin"
        usn_file = part_dir / "usn_journal_partition_0.bin"
        logfile_file = part_dir / "logs_partition_0.txt"
        volume_file = part_dir / "registry_partition_0.txt"

        mft_data = None
        usn_data = None
        logfile_data = None
        volume_created = None
        os_install_time = None

        if mft_file.exists():
            with open(mft_file, "rb") as f:
                mft_data = f.read()

        if usn_file.exists():
            with open(usn_file, "rb") as f:
                usn_data = f.read()

        mft_parser = MFTParser(mft_data) if mft_data else None
        usn_parser = USNJournalParser(usn_data) if usn_data else None

        if mft_parser:
            detector = create_detector_from_parsers(
                mft_parser=mft_parser,
                usn_parser=usn_parser,
                logfile_parser=None,
                volume_created=volume_created,
                os_install_time=os_install_time,
            )

            for record in mft_parser.get_file_records():
                if not record.filename_primary:
                    continue

                si_timestamps = {}
                fn_timestamps = {}

                if record.si_attribute:
                    si_timestamps = {
                        "created": record.si_attribute.created.to_datetime(),
                        "modified": record.si_attribute.modified.to_datetime(),
                        "accessed": record.si_attribute.accessed.to_datetime(),
                        "mft_modified": record.si_attribute.mft_modified.to_datetime(),
                    }

                if record.fn_attributes:
                    fn = record.fn_attributes[0]
                    fn_timestamps = {
                        "created": fn.created.to_datetime(),
                        "modified": fn.modified.to_datetime(),
                        "accessed": fn.accessed.to_datetime(),
                        "mft_modified": fn.mft_modified.to_datetime(),
                    }

                result = detector.analyze_file(
                    filename=record.filename_primary,
                    file_ref=record.record_number,
                    record_sequence_number=record.sequence_number,
                    si_timestamps=si_timestamps,
                    fn_timestamps=fn_timestamps,
                )

                results["summary"]["total_files_analyzed"] += 1

                if result.is_timestomped:
                    results["summary"]["timestomped_files"] += 1

                if result.overall_severity == "HIGH":
                    results["summary"]["high_severity_count"] += 1
                elif result.overall_severity == "CRITICAL":
                    results["summary"]["critical_severity_count"] += 1
                elif result.overall_severity == "MEDIUM":
                    results["summary"]["medium_severity_count"] += 1

                if result.indicators:
                    results["file_results"].append(
                        {
                            "filename": result.filename,
                            "file_reference": result.file_reference,
                            "sequence_number": result.record_sequence_number,
                            "si_fn_created_delta": result.si_fn_created_delta,
                            "si_fn_modified_delta": result.si_fn_modified_delta,
                            "overall_score": result.overall_score,
                            "overall_severity": result.overall_severity,
                            "is_timestomped": result.is_timestomped,
                            "indicators": [
                                {
                                    "check": i.check_name,
                                    "check_number": i.check_number,
                                    "severity": i.severity,
                                    "confidence": i.confidence,
                                    "description": i.description,
                                    "evidence": i.evidence,
                                }
                                for i in result.indicators
                            ],
                        }
                    )

            batch_patterns = detector.analyze_batch_patterns()
            results["batch_patterns"] = [
                {
                    "check": p.check_name,
                    "severity": p.severity,
                    "description": p.description,
                    "evidence": p.evidence,
                }
                for p in batch_patterns
            ]

    results["file_results"] = sorted(
        results["file_results"],
        key=lambda x: x["overall_score"],
        reverse=True,
    )[:100]

    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="FreeKhana Unified Disk Forensic Pipeline"
    )
    parser.add_argument(
        "image", help="Path to disk image or output directory (if --skip-extraction)"
    )
    parser.add_argument(
        "-o", "--output", default="forensic_output", help="Output directory"
    )
    parser.add_argument("-k", "--api-key", help="OpenRouter API Key")
    parser.add_argument(
        "--skip-extraction", action="store_true", help="Skip extraction phase"
    )
    parser.add_argument("--ollama-url", help="Ollama API URL")
    parser.add_argument("--model", help="AI Model to use")

    args = parser.parse_args()

    api_key = args.api_key or os.environ.get("OPENROUTER_API_KEY")

    if args.skip_extraction:
        run_pipeline(None, args.image, api_key, True, args.ollama_url, args.model)
    else:
        run_pipeline(
            args.image, args.output, api_key, False, args.ollama_url, args.model
        )
