"""
SIEM Backend API - Python/FastAPI
Main entry point for the log parsing and analysis API
"""

import os
import sys

# Load environment variables from .env file
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))

from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from typing import Optional, List, Dict, Any
import re
import json
import uuid
from datetime import datetime

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

try:
    from parsers import auto_parse, detect_log_type, generate_stats as gen_stats
    from detectors.alerts import run_detections

    PARSERS_AVAILABLE = True
except ImportError as e:
    print(f"Import warning: {e}")
    PARSERS_AVAILABLE = False

try:
    from ml.classifier import detect_ml_attacks, enrich_entries_with_attacks

    ML_AVAILABLE = True
except ImportError as e:
    print(f"ML import warning: {e}")
    ML_AVAILABLE = False
    detect_ml_attacks = None
    enrich_entries_with_attacks = None

app = FastAPI(title="FreeKhana SIEM API", version="2.0.0")


@app.on_event("startup")
async def startup_event():
    """Initialize SOC Analyst Cloud AI"""
    print("Starting FreeKhana SIEM API...")
    api_key = os.environ.get("OPENROUTER_API_KEY")
    if api_key:
        print("SOC Analyst AI: OpenRouter Cloud AI configured")
        client = _get_soc_client()
        if client:
            print("[OK] SOC Analyst AI ready (using OpenRouter cloud)")
        else:
            print("[WARN] SOC Analyst AI: Could not initialize OpenRouter client")
    else:
        print(
            "SOC Analyst AI: OPENROUTER_API_KEY not set - will use rule-based fallback"
        )


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Attack patterns for keyword-based detection
ATTACK_PATTERNS = {
    "bruteforce": {
        "patterns": [
            r"Failed password",
            r"authentication failure",
            r"Invalid user",
            r"Failed password for invalid user",
            r"too many failed attempts",
        ],
        "weight": 0.85,
    },
    "password_spray": {
        "patterns": [
            r"Failed password",
        ],
        "weight": 0.75,
    },
    "sql_injection": {
        "patterns": [
            r"' OR '1'='1",
            r"UNION SELECT",
            r"1=1--",
            r"admin'--",
            r"DROP TABLE",
            r"UNION ALL",
            r"';--",
        ],
        "weight": 0.95,
    },
    "xss_attack": {
        "patterns": [
            r"<script>",
            r"javascript:",
            r"onerror=",
            r"onload=",
            r"<img src=x",
        ],
        "weight": 0.90,
    },
    "command_injection": {
        "patterns": [
            r"; ls -la",
            r"\| cat /etc/passwd",
            r"`whoami`",
            r"$(whoami)",
            r"\|\|.*whoami",
            r";\s*rm\s+-rf",
        ],
        "weight": 0.90,
    },
    "path_traversal": {
        "patterns": [
            r"\.\.\/",
            r"\.\.\\",
            r"%2e%2e",
        ],
        "weight": 0.85,
    },
    "port_scan": {
        "patterns": [
            r"SYN scan",
            r"NULL scan",
            r"XMAS scan",
            r"FIN scan",
            r"IPTABLES DROP",
            r"DROP.*PROTO=TCP",
        ],
        "weight": 0.80,
    },
    "ddos": {
        "patterns": [
            r"DDOS",
            r"distributed denial",
            r"flood",
            r"Teardown TCP connection",
        ],
        "weight": 0.85,
    },
    "privilege_escalation": {
        "patterns": [
            r"sudo:",
            r"su: root",
            r"su\(",
            r"admin.*privilege",
            r"GRANT ALL",
        ],
        "weight": 0.80,
    },
}


def detect_attack_type(message: str) -> tuple[str, float]:
    """Detect attack type from log message using keyword patterns"""
    message_lower = message.lower()

    best_attack = None
    best_confidence = 0.0

    for attack_type, config in ATTACK_PATTERNS.items():
        for pattern in config["patterns"]:
            if re.search(pattern, message, re.IGNORECASE):
                if config["weight"] > best_confidence:
                    best_attack = attack_type
                    best_confidence = config["weight"]

    if best_attack is None:
        return "safe", 0.0
    return best_attack, best_confidence


@app.get("/")
async def root():
    return {
        "status": "ok",
        "name": "FreeKhana SIEM API",
        "version": "2.0.0",
        "features": [
            "Multi-log parsing (50+ log types)",
            "ML-based attack detection",
            "Keyword-based pattern detection",
            "Cross-log correlation",
        ],
    }


@app.post("/parse")
async def parse_logs(
    content: Optional[str] = Form(None),
    file: Optional[UploadFile] = File(None),
    forceType: Optional[str] = Form(None),
):
    """Parse log content and detect attacks"""

    # Handle file upload or text content
    if file:
        content_bytes = await file.read()
        content = content_bytes.decode("utf-8", errors="ignore")
    elif not content:
        raise HTTPException(status_code=400, detail="No log content provided")

    if not content or len(content.strip()) == 0:
        raise HTTPException(status_code=400, detail="No log content provided")

    if PARSERS_AVAILABLE:
        # Use the new parser with full detection
        result = auto_parse(content, forceType)
        entries = result.get("entries", [])

        # Add keyword-based attack detection
        for entry in entries:
            attack_type, confidence = detect_attack_type(entry.get("message", ""))
            if attack_type != "safe":
                entry["attackType"] = attack_type
                entry["attackConfidence"] = confidence
                entry["severity"] = "warning"
                entry["tags"] = entry.get("tags", []) + ["attack", attack_type]

        # Run ML detection if available
        if detect_ml_attacks:
            ml_preds = detect_ml_attacks(entries)

        # Run alerts detection
        alerts = run_detections(entries) if run_detections else []

        # Count attacks
        attack_entries = [e for e in entries if e.get("attackType")]
        attack_types = list(
            set(e["attackType"] for e in attack_entries if e.get("attackType"))
        )

        risk_score = min(len(attack_entries) * 10, 100)

        return {
            "success": True,
            "detectedType": result.get("detectedType", "unknown"),
            "totalLines": result.get("stats", {}).get("total", 0),
            "parsedLines": len(entries),
            "failedLines": result.get("stats", {}).get("failed", 0),
            "entries": entries,
            "alerts": alerts,
            "stats": result.get("stats", {}),
            "attackSummary": {
                "totalAttacks": len(attack_entries),
                "attackTypes": attack_types,
                "riskScore": risk_score,
            },
        }
    else:
        # Fallback to simple parsing
        lines = [l for l in content.split("\n") if l.strip()]
        entries = []

        for line in lines:
            attack_type, confidence = detect_attack_type(line)
            entry = {
                "id": str(uuid.uuid4()),
                "timestamp": datetime.now().isoformat(),
                "logType": "unknown",
                "severity": "warning" if attack_type != "safe" else "info",
                "source": {"ip": extract_ip(line)},
                "user": {},
                "action": "unknown",
                "outcome": "failure" if "fail" in line.lower() else "success",
                "message": line,
                "rawLine": line,
                "fields": {},
                "tags": ["attack"] if attack_type != "safe" else [],
                "attackType": attack_type if attack_type != "safe" else None,
                "attackConfidence": confidence if attack_type != "safe" else None,
            }
            entries.append(entry)

        return {
            "success": True,
            "detectedType": "unknown",
            "totalLines": len(lines),
            "parsedLines": len(entries),
            "failedLines": 0,
            "entries": entries,
            "stats": gen_stats(entries) if gen_stats else {},
        }


def extract_ip(line: str) -> Optional[str]:
    """Extract IP address from log line"""
    ip_pattern = r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
    match = re.search(ip_pattern, line)
    return match.group(1) if match else None


@app.post("/parse/file")
async def parse_log_file(
    file: UploadFile = File(...), forceType: Optional[str] = Form(None)
):
    """Parse uploaded log file"""
    content = await file.read()
    content_str = content.decode("utf-8", errors="ignore")

    # Delegate to parse_logs
    return await parse_logs(content=content_str, forceType=forceType)


@app.post("/parse/chunked")
async def parse_chunked_logs(
    chunks: List[str] = Form(...), fileName: Optional[str] = Form(None)
):
    """Parse pre-chunked log content"""
    content = "\n".join(chunks)
    return await parse_logs(content=content)


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "ml_enabled": PARSERS_AVAILABLE,
        "parsers_available": PARSERS_AVAILABLE,
    }


# ============================================================================
# SOC Analyst LLM Endpoints
# ============================================================================

from pydantic import BaseModel
from typing import List, Dict


class LogAnalysisRequest(BaseModel):
    log_entry: str
    log_type: Optional[str] = "unknown"


class ChatRequest(BaseModel):
    message: str
    context: Optional[List[Dict]] = []
    logData: Optional[Dict] = None


class LogAnalysisResponse(BaseModel):
    analysis: str
    attack_detected: bool
    severity: str


class ChatResponse(BaseModel):
    response: str


# SOC Analyst LLM Integration - Using OpenRouter Cloud AI
_soc_openrouter_client = None
_soc_model = "google/gemini-2.0-flash-001"


def _get_soc_client():
    """Get or create OpenRouter client for SOC Analyst"""
    global _soc_openrouter_client
    if _soc_openrouter_client is None:
        api_key = os.environ.get("OPENROUTER_API_KEY")
        if api_key:
            sys.path.insert(
                0, os.path.join(os.path.dirname(__file__), "..", "imageProcessor")
            )
            try:
                from ai_forensic_analyzer import OpenRouterClient

                _soc_openrouter_client = OpenRouterClient(api_key, _soc_model)
            except ImportError:
                print("Warning: Could not import OpenRouterClient")
    return _soc_openrouter_client


def analyze_log_rule_based(log_entry: str, log_type: str) -> str:
    """Rule-based log analysis as fallback"""
    log_lower = log_entry.lower()

    # Check for common attack patterns
    if "failed password" in log_lower or "authentication failure" in log_lower:
        failed_count = log_lower.count("failed")
        if failed_count >= 3:
            return f"""ALERT: BRUTE FORCE ATTACK DETECTED

Attack Pattern: Multiple failed authentication attempts
Confidence: HIGH (90%)

Key Indicators:
- {failed_count} failed login attempts detected
- Target: Authentication system
- Log Type: {log_type}

MITRE ATT&CK: T1110 - Brute Force

Recommended Actions:
1. Check if any attempts were successful
2. Review user account activity
3. Implement rate limiting
4. Enable account lockout policy
5. Consider IP blocking if attacks persist"""

    if any(
        x in log_lower for x in ["sql", "union", "select", "drop", "insert", "update"]
    ):
        return f"""WARNING: POTENTIAL SQL INJECTION ATTEMPT

Attack Pattern: SQL keywords detected in log entry
Confidence: MEDIUM (70%)

Key Indicators:
- SQL commands found in {log_type} log
- Potential database attack vector

MITRE ATT&CK: T1190 - Exploit Public-Facing Application

Recommended Actions:
1. Verify input validation on application
2. Check for successful database access
3. Review WAF logs
4. Audit database queries"""

    if any(x in log_lower for x in ["sudo", "privilege", "escalation", "root"]):
        return f"""WARNING: PRIVILEGE ESCALATION ATTEMPT

Attack Pattern: Administrative access attempts detected
Confidence: MEDIUM (65%)

Key Indicators:
- Privilege escalation commands
- Administrative access attempts

MITRE ATT&CK: T1078 - Valid Accounts

Recommended Actions:
1. Verify user authorization
2. Check command history
3. Monitor for further escalation attempts"""

    if any(x in log_lower for x in ["outbound", "external", "exfil", "transfer"]):
        return f"""INFO: POTENTIAL DATA EXFILTRATION

Attack Pattern: Unusual outbound data transfer
Confidence: MEDIUM (60%)

Key Indicators:
- External connection attempts
- Data transfer activity

MITRE ATT&CK: T1041 - Exfiltration Over C2 Channel

Recommended Actions:
1. Verify data transfer legitimacy
2. Check DLP logs
3. Monitor destination IP reputation"""

    # Default analysis
    return f"""INFO: Log Analysis Complete

Log Type: {log_type}
Analysis: No obvious attack patterns detected in this entry.

General Observations:
- Standard log entry format
- No immediate threat indicators
- Recommendation: Monitor in context with other logs

Next Steps:
1. Check surrounding log entries for patterns
2. Correlate with other data sources
3. Set up alerting for similar events if needed

Note: This is a preliminary analysis. Manual review by a security analyst is recommended for critical systems."""


def analyze_with_llm(log_entry: str, log_type: str) -> str:
    """Analyze log using OpenRouter Cloud AI with rule-based fallback"""
    client = _get_soc_client()

    if client is None:
        return analyze_log_rule_based(log_entry, log_type)

    try:
        system_prompt = """You are an expert SOC (Security Operations Center) analyst. Analyze the given log entry for security threats, anomalies, and potential attacks. 

Provide your analysis in this format:
1. THREAT ASSESSMENT: [CRITICAL/HIGH/MEDIUM/LOW/INFO]
2. ATTACK TYPE: [Specific attack type if detected, or "None detected"]
3. KEY INDICATORS: [List suspicious elements found]
4. EXPLANATION: [Brief explanation of why this is/isn't suspicious]
5. RECOMMENDATION: [Action to take]

Be concise but thorough. Focus on actionable security insights."""

        user_prompt = f"Log Type: {log_type}\n\nLog Entry:\n{log_entry}"

        response = client.chat(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            max_tokens=500,
            temperature=0.3,
        )

        if response and len(response) > 10:
            return response
        else:
            print("Warning: Cloud AI returned empty/short response, using fallback")
            return analyze_log_rule_based(log_entry, log_type)

    except Exception as e:
        print(f"Error in Cloud AI analysis: {e}")
        return analyze_log_rule_based(log_entry, log_type)


def generate_soc_response(message: str) -> str:
    """Generate a SOC analyst response using rule-based fallback"""
    message_lower = message.lower()

    # Common security questions and answers
    responses = {
        "brute force": """ALERT: Brute Force Attack

A brute force attack is when an attacker tries to gain access by systematically guessing passwords or encryption keys.

Key Indicators:
- Multiple failed login attempts
- Rapid succession of authentication failures
- Same IP or user with repeated failures
- Successful login after many failures

MITRE ATT&CK: T1110 - Brute Force

Recommended Actions:
1. Implement account lockout policies
2. Enable multi-factor authentication (MFA)
3. Set up rate limiting on login endpoints
4. Monitor for unusual login patterns
5. Use strong, unique passwords""",
        "sql injection": """ALERT: SQL Injection (SQLi)

SQL injection is a code injection attack where malicious SQL statements are inserted into application queries.

How It Works:
Attackers input malicious SQL code into form fields. If not properly sanitized, the database executes the malicious commands.

Example:
Input: admin' OR '1'='1'--
Result: Bypasses authentication

MITRE ATT&CK: T1190 - Exploit Public-Facing Application

Prevention:
1. Use parameterized queries/prepared statements
2. Input validation and sanitization
3. Principle of least privilege for DB accounts
4. Web Application Firewall (WAF)
5. Regular security testing""",
        "ddos": """ALERT: DDoS Attack (Distributed Denial of Service)

A DDoS attack attempts to make a service unavailable by overwhelming it with traffic from multiple sources.

Types:
- Volumetric: Floods bandwidth (UDP floods, ICMP floods)
- Protocol: Targets network layer (SYN floods, Ping of Death)
- Application: Targets web servers (HTTP floods, Slowloris)

MITRE ATT&CK: T1498 - Network Denial of Service

Mitigation:
1. DDoS protection services (Cloudflare, AWS Shield)
2. Rate limiting and traffic filtering
3. Load balancing across multiple servers
4. Blackhole routing for attack traffic
5. Incident response plan""",
        "malware": """ALERT: Malware Analysis

Malware is malicious software designed to damage, disrupt, or gain unauthorized access to systems.

Common Types:
- Viruses: Self-replicating, attach to programs
- Trojans: Disguised as legitimate software
- Ransomware: Encrypts data for ransom
- Spyware: Steals information secretly
- Worms: Self-spreading across networks

Detection Indicators:
- Unknown processes running
- Network connections to suspicious IPs
- File system modifications
- Registry changes for persistence

Response:
1. Isolate infected systems immediately
2. Capture memory dumps and disk images
3. Identify malware family and capabilities
4. Check for lateral movement
5. Eradicate and recover from clean backups""",
    }

    # Check for keywords in the message
    for keyword, response in responses.items():
        if keyword in message_lower:
            return response

    # Default response
    return """I'm your SOC Analyst AI assistant. I can help you with:

Log Analysis:
- Authentication anomalies
- Network traffic patterns
- Malware indicators
- Attack chain reconstruction

Security Concepts:
- Attack techniques and tactics
- Incident response procedures
- Threat hunting methodologies
- Security best practices

Try asking about:
- "What is a brute force attack?"
- "How to detect SQL injection?"
- "Explain DDoS mitigation"
- "Analyze this suspicious log"

Note: I'm currently operating in knowledge-based mode. For real-time log analysis, please share the log entry you'd like me to examine."""


def build_log_context(logData: Dict) -> str:
    """Build a context string from parsed log data"""
    if not logData:
        return ""

    context_parts = []

    # Summary stats
    if isinstance(logData, dict):
        # Parse response
        stats = logData.get("stats", {})
        alerts = logData.get("alerts", [])
        entries = logData.get("entries", [])
        attackSummary = logData.get("attackSummary", {})
        detectedType = logData.get("detectedType", "unknown")

        context_parts.append("=== LOG ANALYSIS SUMMARY ===")
        context_parts.append(f"Detected Log Type: {detectedType}")

        if stats:
            bySeverity = stats.get("bySeverity", {})
            if bySeverity:
                context_parts.append(f"Severity Distribution: {bySeverity}")

            topSources = stats.get("topSources", [])[:5]
            if topSources:
                sources = ", ".join(
                    [f"{s.get('ip')}: {s.get('count')}" for s in topSources]
                )
                context_parts.append(f"Top Source IPs: {sources}")

            timeline = stats.get("timeline", [])
            if timeline:
                context_parts.append(f"Timeline spans {len(timeline)} time points")

        if attackSummary:
            totalAttacks = attackSummary.get("totalAttacks", 0)
            attackTypes = attackSummary.get("attackTypes", [])
            riskScore = attackSummary.get("riskScore", 0)
            context_parts.append(f"Attacks Detected: {totalAttacks}")
            if attackTypes:
                context_parts.append(f"Attack Types: {', '.join(attackTypes)}")
            context_parts.append(f"Risk Score: {riskScore}/100")

        # Sample entries with issues
        entries_with_attacks = [e for e in entries if e.get("attackType")]
        if entries_with_attacks:
            context_parts.append(
                f"\n=== SAMPLE ATTACK LOGS ({len(entries_with_attacks)} total) ==="
            )
            for entry in entries_with_attacks[:10]:
                ts = entry.get("timestamp", "N/A")
                attack = entry.get("attackType", "unknown")
                src_ip = entry.get("source", {}).get("ip", "N/A")
                msg = entry.get("message", "")[:100]
                context_parts.append(f"[{ts}] {attack} from {src_ip}: {msg}")

        # Alerts
        if alerts:
            context_parts.append(f"\n=== ALERTS ({len(alerts)} total) ===")
            for alert in alerts[:5]:
                title = alert.get("title", "Unknown")
                severity = alert.get("severity", "unknown")
                src = ", ".join(alert.get("sourceIps", [])[:3])
                context_parts.append(f"- [{severity.upper()}] {title} (Source: {src})")

    return "\n".join(context_parts)


def chat_with_llm(
    message: str, context: List[Dict] = [], logData: Optional[Dict] = None
) -> str:
    """Chat with OpenRouter Cloud AI with rule-based fallback"""
    client = _get_soc_client()

    if client is None:
        return generate_soc_response(message)

    try:
        system_prompt = """You are an expert SOC (Security Operations Center) analyst AI assistant. You help security analysts understand threats, analyze logs, and respond to incidents.

You have access to parsed log data including:
- Log statistics (severity distribution, top sources, timeline)
- Detected attacks and their confidence levels
- Alert details
- Risk scores

When answering questions:
1. Reference the actual log data when applicable
2. Provide specific details (IPs, timestamps, attack types) from the logs
3. Explain what the data means in security context
4. Suggest actionable recommendations

Be helpful, accurate, and concise. Focus on actionable security insights."""

        context_str = ""
        if context:
            context_str = "\n\nPrevious conversation context:\n"
            for msg in context[-3:]:
                role = msg.get("role", "user")
                content = msg.get("content", "")
                context_str += f"{role.capitalize()}: {content}\n"
            context_str += "\n"

        # Add log data context
        log_context = build_log_context(logData) if logData else ""
        if log_context:
            context_str += f"\n{log_context}\n"

        user_prompt = f"{context_str}User question: {message}"

        response = client.chat(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            max_tokens=800,
            temperature=0.5,
        )

        if response and len(response) > 10:
            return response
        else:
            print("Warning: Cloud AI returned empty/short response, using fallback")
            return generate_soc_response(message)

    except Exception as e:
        print(f"Error in Cloud AI chat: {e}")
        return generate_soc_response(message)


@app.post("/soc-analyze", response_model=LogAnalysisResponse)
async def soc_analyze_log(request: LogAnalysisRequest):
    """Analyze a log entry using SOC Analyst LLM"""
    try:
        log_type = request.log_type or "unknown"
        analysis = analyze_with_llm(request.log_entry, log_type)

        # Parse attack indicators
        attack_detected = any(
            keyword in analysis.lower()
            for keyword in [
                "attack",
                "threat",
                "malicious",
                "suspicious",
                "breach",
                "compromise",
                "brute force",
            ]
        )

        severity = "low"
        if "critical" in analysis.lower():
            severity = "critical"
        elif "high" in analysis.lower():
            severity = "high"
        elif "medium" in analysis.lower():
            severity = "medium"

        return LogAnalysisResponse(
            analysis=analysis, attack_detected=attack_detected, severity=severity
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"LLM analysis error: {str(e)}")


@app.post("/soc-chat", response_model=ChatResponse)
async def soc_chat(request: ChatRequest):
    """Chat with SOC Analyst LLM"""
    try:
        response = chat_with_llm(
            request.message, request.context or [], request.logData
        )
        return ChatResponse(response=response)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Chat error: {str(e)}")


@app.get("/soc-health")
async def soc_health():
    """Check SOC Analyst LLM health"""
    client = _get_soc_client()
    api_key_configured = bool(os.environ.get("OPENROUTER_API_KEY"))
    return {
        "status": "ok" if client else "unavailable",
        "llm_loaded": client is not None,
        "model": f"OpenRouter Cloud AI ({_soc_model})"
        if client
        else "Rule-based fallback",
        "api_key_configured": api_key_configured,
    }


# Feedback request/response models
class FeedbackRequest(BaseModel):
    message_id: str
    rating: int
    feedback_text: Optional[str] = ""
    original_prompt: str
    llm_response: str
    log_context: Optional[str] = ""


class FeedbackResponse(BaseModel):
    status: str
    message: str
    training_examples_count: int


class TrainRequest(BaseModel):
    epochs: Optional[int] = 1


class TrainResponse(BaseModel):
    status: str
    message: str


# Local feedback storage
_feedback_storage = []


@app.post("/soc-feedback", response_model=FeedbackResponse)
async def submit_feedback(request: FeedbackRequest):
    """Submit feedback for SOC Analyst LLM responses"""
    try:
        # Store feedback locally
        feedback_entry = {
            "message_id": request.message_id,
            "rating": request.rating,
            "feedback_text": request.feedback_text,
            "original_prompt": request.original_prompt,
            "llm_response": request.llm_response,
            "log_context": request.log_context,
            "timestamp": datetime.now().isoformat(),
        }
        _feedback_storage.append(feedback_entry)

        # Optionally save to file
        try:
            feedback_file = os.path.join(
                os.path.dirname(__file__), "user_feedback.json"
            )
            with open(feedback_file, "w") as f:
                json.dump(_feedback_storage, f, indent=2)
        except:
            pass  # File save is optional

        return FeedbackResponse(
            status="success",
            message="Feedback received and saved for future training!",
            training_examples_count=len(_feedback_storage),
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error saving feedback: {str(e)}")


@app.post("/soc-train", response_model=TrainResponse)
async def train_on_feedback(request: TrainRequest = TrainRequest()):
    """Train the model on accumulated feedback"""
    try:
        if len(_feedback_storage) == 0:
            return TrainResponse(
                status="skipped", message="No feedback available to train on."
            )

        epochs = request.epochs if request else 1

        # Save feedback as training data
        training_data = []
        for fb in _feedback_storage:
            if fb["rating"] == 5 or (fb["rating"] == 1 and fb.get("feedback_text")):
                example = {
                    "instruction": fb["original_prompt"],
                    "input": fb.get("log_context", ""),
                    "output": fb.get("feedback_text")
                    if fb["rating"] == 1 and fb.get("feedback_text")
                    else fb["llm_response"],
                }
                training_data.append(example)

        # Save to training data file
        training_file = os.path.join(
            os.path.dirname(__file__), "feedback_training_data.json"
        )
        with open(training_file, "w") as f:
            json.dump(training_data, f, indent=2)

        return TrainResponse(
            status="success",
            message=f"Training data prepared with {len(training_data)} examples from {len(_feedback_storage)} feedback entries. Run 'python continue_training.py' to retrain the model.",
        )
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Error preparing training: {str(e)}"
        )


@app.get("/soc-feedback/stats")
async def get_feedback_stats():
    """Get feedback statistics"""
    likes = sum(1 for f in _feedback_storage if f.get("rating") == 5)
    dislikes = sum(1 for f in _feedback_storage if f.get("rating") == 1)

    return {
        "total_feedback": len(_feedback_storage),
        "likes": likes,
        "dislikes": dislikes,
        "pending_training": len(_feedback_storage),
    }


# ============================================================================
# Disk Forensics Endpoints
# ============================================================================

import tempfile
import shutil
import threading
import uuid

FORENSIC_STATE = {
    "status": "idle",  # idle, running, completed, error
    "progress": 0,
    "message": "",
    "results": None,
    "error": None,
}
forensic_lock = threading.Lock()


def run_forensic_analysis_async(image_path: str, output_dir: str, temp_dir: str = None):
    """Run forensic analysis in background thread"""
    global FORENSIC_STATE

    try:
        sys.path.insert(
            0,
            os.path.join(
                os.path.dirname(__file__), "..", "forensic-disk-analyzer", "backend"
            ),
        )

        from run_forensic_pipeline import run_pipeline

        with forensic_lock:
            FORENSIC_STATE["status"] = "running"
            FORENSIC_STATE["progress"] = 10
            FORENSIC_STATE["message"] = "Starting forensic analysis pipeline..."

        api_key = os.environ.get("OPENROUTER_API_KEY")
        model = os.environ.get("OPENROUTER_MODEL", "google/gemini-2.0-flash-001")
        ollama_url = os.environ.get("OLLAMA_URL", "http://localhost:11434")

        results = run_pipeline(
            image_path,
            output_dir,
            api_key=api_key,
            model=model,
            ollama_url=ollama_url,
            skip_extraction=False,
        )

        with forensic_lock:
            FORENSIC_STATE["progress"] = 100
            FORENSIC_STATE["status"] = "completed"
            FORENSIC_STATE["message"] = "Analysis complete"
            FORENSIC_STATE["results"] = output_dir
            FORENSIC_STATE["result_data"] = results

    except Exception as e:
        with forensic_lock:
            FORENSIC_STATE["status"] = "error"
            FORENSIC_STATE["error"] = str(e)
            FORENSIC_STATE["message"] = f"Error: {str(e)}"


@app.post("/forensic/analyze")
async def analyze_disk_image(file: UploadFile = File(...)):
    """Upload and analyze a disk image"""
    global FORENSIC_STATE

    if FORENSIC_STATE.get("status") == "running":
        raise HTTPException(status_code=409, detail="Analysis already in progress")

    # Create project folder for forensic results
    project_root = os.path.dirname(os.path.abspath(__file__))
    forensic_base = os.path.join(project_root, "forensic_results")
    os.makedirs(forensic_base, exist_ok=True)

    analysis_id = str(uuid.uuid4())
    forensic_dir = os.path.join(forensic_base, f"analysis_{analysis_id}")
    os.makedirs(forensic_dir, exist_ok=True)

    temp_dir = forensic_dir

    with forensic_lock:
        FORENSIC_STATE["status"] = "running"
        FORENSIC_STATE["progress"] = 0
        FORENSIC_STATE["message"] = "Uploading disk image..."
        FORENSIC_STATE["results"] = forensic_dir
        FORENSIC_STATE["error"] = None
        FORENSIC_STATE["temp_dir"] = temp_dir

    # Save uploaded file
    filename = file.filename or "disk.dd"
    # Handle E01 format
    if filename.lower().endswith(".e01"):
        image_path = os.path.join(temp_dir, "disk.E01")
    else:
        image_path = os.path.join(temp_dir, filename)

    with open(image_path, "wb") as f:
        content = await file.read()
        f.write(content)

    output_dir = os.path.join(temp_dir, "forensic_output")
    os.makedirs(output_dir, exist_ok=True)

    with forensic_lock:
        FORENSIC_STATE["results"] = output_dir

    thread = threading.Thread(
        target=run_forensic_analysis_async, args=(image_path, output_dir, temp_dir)
    )
    thread.start()

    return {
        "analysisId": analysis_id,
        "status": "started",
        "message": "Disk image uploaded, analysis started",
    }


@app.get("/forensic/status")
async def get_forensic_status():
    """Get forensic analysis status"""
    with forensic_lock:
        current_status = FORENSIC_STATE.get("status", "idle")

        # Auto-detect if results exist on disk
        if current_status == "idle":
            project_root = os.path.dirname(os.path.abspath(__file__))
            forensic_base = os.path.join(project_root, "forensic_results")
            if os.path.exists(forensic_base):
                analyses = [
                    d for d in os.listdir(forensic_base) if d.startswith("analysis_")
                ]
                if analyses:
                    analyses.sort(
                        key=lambda x: os.path.getmtime(os.path.join(forensic_base, x)),
                        reverse=True,
                    )
                    output_dir = os.path.join(
                        forensic_base, analyses[0], "forensic_output"
                    )
                    if os.path.exists(output_dir):
                        # Check if results exist
                        if any(
                            f.endswith(".json")
                            for f in os.listdir(output_dir)
                            if "analysis" in f or "report" in f
                        ):
                            current_status = "completed"

        return {
            "status": current_status,
            "progress": 100
            if current_status == "completed"
            else FORENSIC_STATE.get("progress", 0),
            "message": "Analysis complete"
            if current_status == "completed"
            else FORENSIC_STATE.get("message", ""),
        }


@app.get("/forensic/results")
async def get_forensic_results():
    """Get forensic analysis results"""
    with forensic_lock:
        # Prioritize in-memory result_data if available and valid
        result_data = FORENSIC_STATE.get("result_data")
        if (
            result_data
            and isinstance(result_data, dict)
            and FORENSIC_STATE.get("status") == "completed"
        ):
            results = result_data

            # Load AI HTML report if it exists
            output_dir = FORENSIC_STATE.get("results")
            if output_dir:
                report_path = os.path.join(output_dir, "live_tampering_report.html")
                if os.path.exists(report_path):
                    with open(report_path, "r") as f:
                        results["ai_report_html"] = f.read()

            return {"status": "completed", "results": results, "output_dir": output_dir}

        output_dir = FORENSIC_STATE.get("results")

        # Auto-discover existing results if in-memory state is lost
        if not output_dir or not os.path.exists(output_dir):
            project_root = os.path.dirname(os.path.abspath(__file__))
            forensic_base = os.path.join(project_root, "forensic_results")
            if os.path.exists(forensic_base):
                # Find most recent analysis
                analyses = [
                    d for d in os.listdir(forensic_base) if d.startswith("analysis_")
                ]
                if analyses:
                    # Sort by modification time, get most recent
                    analyses.sort(
                        key=lambda x: os.path.getmtime(os.path.join(forensic_base, x)),
                        reverse=True,
                    )
                    output_dir = os.path.join(
                        forensic_base, analyses[0], "forensic_output"
                    )

        if not output_dir or not os.path.exists(output_dir):
            return {
                "status": "idle",
                "results": None,
                "message": "No analysis results found",
            }

        results_dir = output_dir
        results = {}

        layered_file = os.path.join(results_dir, "layered_analysis_results.json")
        if os.path.exists(layered_file):
            with open(layered_file) as f:
                results["layered_analysis"] = json.load(f)

        timestomp_file = os.path.join(results_dir, "timestomp_report.json")
        if os.path.exists(timestomp_file):
            with open(timestomp_file) as f:
                results["timestomping"] = json.load(f)

        advanced_file = os.path.join(results_dir, "advanced_antiforensic_results.json")
        if os.path.exists(advanced_file):
            with open(advanced_file) as f:
                results["advanced_analysis"] = json.load(f)

        ai_file = os.path.join(results_dir, "ai_analysis_results.json")
        if os.path.exists(ai_file):
            with open(ai_file) as f:
                results["ai_analysis"] = json.load(f)

        # Copied files detection logic (standalone load)
        copied_files = []
        # Try to find possiblyCopied.txt
        for f in os.listdir(results_dir):
            if f.startswith("possiblyCopied") and f.endswith(".txt"):
                with open(os.path.join(results_dir, f), "r", errors="ignore") as file:
                    content = f.read()
                    for line in content.split("\n"):
                        if (
                            any(line.startswith(x) for x in ["=", "Total", "Filename"])
                            or not line.strip()
                        ):
                            continue
                        dates = re.findall(
                            r"\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}", line
                        )
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
                                            "reason": "Modified < Created",
                                        }
                                    )
                break

        if copied_files:
            results["copied_files"] = {
                "files": copied_files,
                "count": len(copied_files),
            }

        # Load AI HTML Report
        report_path = os.path.join(results_dir, "live_tampering_report.html")
        if os.path.exists(report_path):
            with open(report_path, "r") as f:
                results["ai_report_html"] = f.read()

        # Check for alternative result files from forensic_tasks
        layered_alt = os.path.join(results_dir, "layered_timestomp_analysis.json")
        if os.path.exists(layered_alt):
            with open(layered_alt) as f:
                results["layered_timestomp_analysis"] = json.load(f)

        antiforensic_file = os.path.join(results_dir, "antiforensic_analysis.json")
        if os.path.exists(antiforensic_file):
            with open(antiforensic_file) as f:
                results["antiforensic_analysis"] = json.load(f)

        # Auto-complete status if we found results
        status = "completed" if results else FORENSIC_STATE.get("status", "idle")

        return {"status": status, "results": results, "output_dir": output_dir}


from fastapi.responses import Response
from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle


@app.post("/api/export-pdf")
async def export_forensic_pdf(data: Dict[str, Any]):
    """Generate a forensic PDF report from results"""
    results = data.get("results")
    if not results:
        raise HTTPException(status_code=400, detail="No results provided")

    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []

    # Title
    elements.append(Paragraph("Forensic Analysis Report", styles["Title"]))
    elements.append(Spacer(1, 12))

    # Meta Info
    elements.append(
        Paragraph(f"Analyzed At: {results.get('analyzed_at', 'N/A')}", styles["Normal"])
    )
    elements.append(
        Paragraph(
            f"Output Directory: {results.get('output_directory', 'N/A')}",
            styles["Normal"],
        )
    )
    elements.append(Spacer(1, 24))

    # Summary Stats
    elements.append(Paragraph("Analysis Summary", styles["Heading2"]))
    layered_data = results.get("layered_analysis", {})
    advanced_data = results.get("advanced_analysis", {})
    summary_data = layered_data.get("analysis_summary", {})

    # Get correct values from the new JSON structure
    total_files = summary_data.get("total_files_analyzed", 0)
    if total_files == 0:
        # Try getting from advanced_analysis
        total_files = advanced_data.get("summary", {}).get("total_indicators", 0)

    suspicious_files = summary_data.get("suspicious_files", 0)
    if suspicious_files == 0:
        # Try getting from timestomping or advanced_analysis
        suspicious_files = (
            results.get("timestomping", {})
            .get("summary", {})
            .get("possibly_copied_count", 0)
        )
        if suspicious_files == 0:
            suspicious_files = advanced_data.get("summary", {}).get(
                "total_timestomping_indicators", 0
            )

    anti_forensic_hits = advanced_data.get("summary", {}).get("total_indicators", 0)

    stats = [
        ["Metric", "Value"],
        ["Total Files Analyzed", total_files],
        ["Suspicious Files Detected", suspicious_files],
        ["Advanced Anti-Forensic Hits", anti_forensic_hits],
    ]
    t = Table(stats, colWidths=[200, 100])
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("GRID", (0, 0), (-1, -1), 1, colors.black),
            ]
        )
    )
    elements.append(t)
    elements.append(Spacer(1, 24))

    # AI Summary
    ai_data = results.get("ai_analysis")
    if ai_data and "summary" in ai_data:
        elements.append(Paragraph("AI Forensic Insights", styles["Heading2"]))
        elements.append(Paragraph(ai_data["summary"], styles["Normal"]))
        elements.append(Spacer(1, 12))

        if "findings" in ai_data:
            for f in ai_data["findings"]:
                elements.append(
                    Paragraph(
                        f"• {f.get('technique', 'Detection')}: {f.get('explanation', '')}",
                        styles["Normal"],
                    )
                )
                elements.append(Spacer(1, 6))
        elements.append(Spacer(1, 12))

    # Findings Table
    elements.append(Paragraph("Top Suspicious Findings", styles["Heading2"]))

    # Try different sources for findings
    findings = results.get("layered_analysis", {}).get("suspicious_files", [])

    # If no findings, try copied files
    if not findings:
        copied = results.get("copied_files", {}).get("files", [])
        if copied:
            findings = [
                {
                    "filename": f.get("filename", "Unknown"),
                    "explanation": f"Created: {f.get('created')} Modified: {f.get('modified')}",
                }
                for f in copied[:30]
            ]

    # If still no findings, try advanced analysis indicators
    if not findings:
        advanced = results.get("advanced_analysis", {})
        if advanced.get("shadow_copy_deletion"):
            findings.append(
                {
                    "filename": "Shadow Copies",
                    "explanation": "Shadow copy deletion detected",
                }
            )
        if advanced.get("log_clearing"):
            findings.append(
                {"filename": "Event Logs", "explanation": "Log clearing detected"}
            )
        if advanced.get("file_deletion"):
            findings.append(
                {"filename": "Files", "explanation": "File deletion detected"}
            )

    if findings:
        f_data = [["Filename", "Reason"]]
        for f in findings:
            f_data.append([f.get("filename", "Unknown"), f.get("explanation", "N/A")])

        ft = Table(f_data, colWidths=[200, 300])
        ft.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.darkblue),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )
        elements.append(ft)

    doc.build(elements)

    return Response(
        content=buffer.getvalue(),
        media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=Forensic_Report.pdf"},
    )


@app.get("/forensic/clear")
async def clear_forensic_state():
    """Clear forensic analysis state"""
    global FORENSIC_STATE
    with forensic_lock:
        FORENSIC_STATE = {
            "status": "idle",
            "progress": 0,
            "message": "",
            "results": None,
            "error": None,
        }
    return {"status": "cleared"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8788)
