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
    from ml.classifier import detect_ml_attacks, enrich_entries_with_attacks

    PARSERS_AVAILABLE = True
except ImportError:
    PARSERS_AVAILABLE = False

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


class LogAnalysisResponse(BaseModel):
    analysis: str
    attack_detected: bool
    severity: str


class ChatResponse(BaseModel):
    response: str


# SOC Analyst LLM Integration - Using OpenRouter Cloud AI
_soc_openrouter_client = None
_soc_model = "meta-llama/llama-3.1-8b-instruct:free"


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


def chat_with_llm(message: str, context: List[Dict] = []) -> str:
    """Chat with OpenRouter Cloud AI with rule-based fallback"""
    client = _get_soc_client()

    if client is None:
        return generate_soc_response(message)

    try:
        system_prompt = """You are an expert SOC (Security Operations Center) analyst AI assistant. You help security analysts understand threats, analyze logs, and respond to incidents.

You can help with:
- Log analysis and threat detection
- Attack technique explanations (MITRE ATT&CK)
- Incident response guidance
- Security best practices
- Malware analysis
- Network forensics

Be helpful, accurate, and concise. When analyzing logs, look for indicators of compromise (IOCs), attack patterns, and provide actionable recommendations."""

        context_str = ""
        if context:
            context_str = "\n\nPrevious conversation context:\n"
            for msg in context[-3:]:
                role = msg.get("role", "user")
                content = msg.get("content", "")
                context_str += f"{role.capitalize()}: {content}\n"
            context_str += "\n"

        user_prompt = f"{context_str}User question: {message}"

        response = client.chat(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            max_tokens=600,
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
        response = chat_with_llm(request.message, request.context or [])
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
# Forensic Analysis Endpoints
# ============================================================================

import threading
from forensic_tasks import task_manager, TaskStatus, FORENSIC_PIPELINE_AVAILABLE


class ForensicStartRequest(BaseModel):
    image_path: str


class ForensicStartResponse(BaseModel):
    task_id: str
    status: str
    message: str


class ForensicStatusResponse(BaseModel):
    task_id: str
    status: str
    progress: int
    stage: str
    message: str
    output_dir: Optional[str] = None
    error: Optional[str] = None


class ForensicFinding(BaseModel):
    technique: str
    severity: str
    evidence: str
    explanation: str
    recommendation: str
    confidence: float


class ForensicResultsResponse(BaseModel):
    task_id: str
    status: str
    output_dir: str
    findings: List[ForensicFinding]
    summary: str
    risk_level: str
    recommendations: List[str]
    timestamp: str
    model: str
    analysis_time_seconds: float


@app.get("/forensics/health")
async def forensics_health():
    return {
        "status": "ok",
        "pipeline_available": FORENSIC_PIPELINE_AVAILABLE,
        "api_key_configured": bool(os.environ.get("OPENROUTER_API_KEY")),
    }


@app.post("/forensics/start", response_model=ForensicStartResponse)
async def start_forensic_analysis(request: ForensicStartRequest):
    if not FORENSIC_PIPELINE_AVAILABLE:
        raise HTTPException(
            status_code=503,
            detail="Forensic pipeline not available. Check server configuration.",
        )

    if not os.environ.get("OPENROUTER_API_KEY"):
        raise HTTPException(
            status_code=503,
            detail="OPENROUTER_API_KEY not configured on server. Please set the environment variable.",
        )

    image_path = request.image_path.strip()
    if not image_path:
        raise HTTPException(status_code=400, detail="Image path is required")

    if not os.path.exists(image_path):
        raise HTTPException(
            status_code=400, detail=f"Image file not found: {image_path}"
        )

    ext = os.path.splitext(image_path)[1].lower()
    if ext not in [".e01", ".dd", ".raw", ".img"]:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported image format: {ext}. Supported formats: .e01, .dd, .raw, .img",
        )

    task = task_manager.create_task(image_path)

    thread = threading.Thread(
        target=task_manager.run_forensic_analysis, args=(task.task_id, image_path)
    )
    thread.daemon = True
    thread.start()

    return ForensicStartResponse(
        task_id=task.task_id,
        status=task.status.value,
        message="Forensic analysis started",
    )


@app.get("/forensics/status/{task_id}", response_model=ForensicStatusResponse)
async def get_forensic_status(task_id: str):
    task = task_manager.get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    return ForensicStatusResponse(
        task_id=task.task_id,
        status=task.status.value,
        progress=task.progress,
        stage=task.stage,
        message=task.message,
        output_dir=task.output_dir,
        error=task.error,
    )


@app.get("/forensics/results/{task_id}", response_model=ForensicResultsResponse)
async def get_forensic_results(task_id: str):
    task = task_manager.get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    if task.status != TaskStatus.COMPLETED:
        raise HTTPException(
            status_code=400,
            detail=f"Task not completed. Current status: {task.status.value}",
        )

    if not task.results:
        raise HTTPException(status_code=500, detail="Results not available")

    results = task.results
    findings = []
    for f in results.get("findings", []):
        findings.append(
            ForensicFinding(
                technique=f.get("technique", "unknown"),
                severity=f.get("severity", "UNKNOWN"),
                evidence=f.get("evidence", "N/A"),
                explanation=f.get("explanation", "N/A"),
                recommendation=f.get("recommendation", "N/A"),
                confidence=f.get("confidence", 0.0),
            )
        )

    return ForensicResultsResponse(
        task_id=task.task_id,
        status=task.status.value,
        output_dir=task.output_dir or "",
        findings=findings,
        summary=results.get("summary", "No summary available"),
        risk_level=results.get("risk_level", "UNKNOWN"),
        recommendations=results.get("recommendations", []),
        timestamp=results.get("timestamp", ""),
        model=results.get("model", ""),
        analysis_time_seconds=results.get("analysis_time_seconds", 0),
    )


@app.get("/forensics/pdf/{task_id}")
async def download_forensic_pdf(task_id: str):
    task = task_manager.get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    if task.status != TaskStatus.COMPLETED:
        raise HTTPException(
            status_code=400,
            detail=f"Task not completed. Current status: {task.status.value}",
        )

    if not task.pdf_path:
        raise HTTPException(
            status_code=404,
            detail="PDF report not available. The analysis may have completed before PDF generation was implemented.",
        )

    if not os.path.exists(task.pdf_path):
        raise HTTPException(status_code=404, detail="PDF file not found on server")

    filename = os.path.basename(task.pdf_path)
    return FileResponse(
        path=task.pdf_path,
        media_type="application/pdf",
        filename=filename,
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8788)
