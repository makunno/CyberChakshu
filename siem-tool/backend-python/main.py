"""
SIEM Backend API - Python/FastAPI
Main entry point for the log parsing and analysis API
"""

import os
import sys

from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional, List, Dict, Any
import re
import json
import uuid
from datetime import datetime

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

try:
    from parsers import auto_parse, detect_log_type, generate_stats as gen_stats
    from detectors.alerts import run_detections
    from ml.classifier import detect_ml_attacks, enrich_entries_with_attacks
    PARSERS_AVAILABLE = True
except ImportError:
    PARSERS_AVAILABLE = False

# SOC Analyst LLM Integration
try:
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer
    from peft import PeftModel
    LLM_AVAILABLE = True
except ImportError:
    LLM_AVAILABLE = False

app = FastAPI(title="FreeKhana SIEM API", version="2.0.0")

@app.on_event("startup")
async def startup_event():
    """Load LLM model on startup"""
    print("Starting FreeKhana SIEM API...")
    if LLM_AVAILABLE:
        print("Loading SOC Analyst LLM model...")
        load_soc_llm()
    else:
        print("LLM libraries not available. SOC chat features disabled.")
        print("Install with: pip install transformers torch peft")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Attack patterns for keyword-based detection
ATTACK_PATTERNS = {
    'bruteforce': {
        'patterns': [
            r'Failed password',
            r'authentication failure',
            r'Invalid user',
            r'Failed password for invalid user',
            r'too many failed attempts',
        ],
        'weight': 0.85
    },
    'password_spray': {
        'patterns': [
            r'Failed password',
        ],
        'weight': 0.75
    },
    'sql_injection': {
        'patterns': [
            r"' OR '1'='1",
            r'UNION SELECT',
            r'1=1--',
            r"admin'--",
            r'DROP TABLE',
            r'UNION ALL',
            r"';--",
        ],
        'weight': 0.95
    },
    'xss_attack': {
        'patterns': [
            r'<script>',
            r'javascript:',
            r'onerror=',
            r'onload=',
            r'<img src=x',
        ],
        'weight': 0.90
    },
    'command_injection': {
        'patterns': [
            r'; ls -la',
            r'\| cat /etc/passwd',
            r'`whoami`',
            r'$(whoami)',
            r'\|\|.*whoami',
            r';\s*rm\s+-rf',
        ],
        'weight': 0.90
    },
    'path_traversal': {
        'patterns': [
            r'\.\.\/',
            r'\.\.\\',
            r'%2e%2e',
        ],
        'weight': 0.85
    },
    'port_scan': {
        'patterns': [
            r'SYN scan',
            r'NULL scan',
            r'XMAS scan',
            r'FIN scan',
            r'IPTABLES DROP',
            r'DROP.*PROTO=TCP',
        ],
        'weight': 0.80
    },
    'ddos': {
        'patterns': [
            r'DDOS',
            r'distributed denial',
            r'flood',
            r'Teardown TCP connection',
        ],
        'weight': 0.85
    },
    'privilege_escalation': {
        'patterns': [
            r'sudo:',
            r'su: root',
            r'su\(',
            r'admin.*privilege',
            r'GRANT ALL',
        ],
        'weight': 0.80
    },
}


def detect_attack_type(message: str) -> tuple[str, float]:
    """Detect attack type from log message using keyword patterns"""
    message_lower = message.lower()
    
    best_attack = None
    best_confidence = 0.0
    
    for attack_type, config in ATTACK_PATTERNS.items():
        for pattern in config['patterns']:
            if re.search(pattern, message, re.IGNORECASE):
                if config['weight'] > best_confidence:
                    best_attack = attack_type
                    best_confidence = config['weight']
    
    if best_attack is None:
        return 'safe', 0.0
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
        ]
    }


@app.post("/parse")
async def parse_logs(
    content: Optional[str] = Form(None),
    file: Optional[UploadFile] = File(None),
    forceType: Optional[str] = Form(None)
):
    """Parse log content and detect attacks"""
    
    # Handle file upload or text content
    if file:
        content_bytes = await file.read()
        content = content_bytes.decode('utf-8', errors='ignore')
    elif not content:
        raise HTTPException(status_code=400, detail="No log content provided")
    
    if not content or len(content.strip()) == 0:
        raise HTTPException(status_code=400, detail="No log content provided")
    
    if PARSERS_AVAILABLE:
        # Use the new parser with full detection
        result = auto_parse(content, forceType)
        entries = result.get('entries', [])
        
        # Add keyword-based attack detection
        for entry in entries:
            attack_type, confidence = detect_attack_type(entry.get('message', ''))
            if attack_type != 'safe':
                entry['attackType'] = attack_type
                entry['attackConfidence'] = confidence
                entry['severity'] = 'warning'
                entry['tags'] = entry.get('tags', []) + ['attack', attack_type]
        
        # Run ML detection if available
        if detect_ml_attacks:
            ml_preds = detect_ml_attacks(entries)
        
        # Run alerts detection
        alerts = run_detections(entries) if run_detections else []
        
        # Count attacks
        attack_entries = [e for e in entries if e.get('attackType')]
        attack_types = list(set(e['attackType'] for e in attack_entries if e.get('attackType')))
        
        risk_score = min(len(attack_entries) * 10, 100)
        
        return {
            "success": True,
            "detectedType": result.get('detectedType', 'unknown'),
            "totalLines": result.get('stats', {}).get('total', 0),
            "parsedLines": len(entries),
            "failedLines": result.get('stats', {}).get('failed', 0),
            "entries": entries,
            "alerts": alerts,
            "stats": result.get('stats', {}),
            "attackSummary": {
                "totalAttacks": len(attack_entries),
                "attackTypes": attack_types,
                "riskScore": risk_score,
            }
        }
    else:
        # Fallback to simple parsing
        lines = [l for l in content.split('\n') if l.strip()]
        entries = []
        
        for line in lines:
            attack_type, confidence = detect_attack_type(line)
            entry = {
                'id': str(uuid.uuid4()),
                'timestamp': datetime.now().isoformat(),
                'logType': 'unknown',
                'severity': 'warning' if attack_type != 'safe' else 'info',
                'source': {'ip': extract_ip(line)},
                'user': {},
                'action': 'unknown',
                'outcome': 'failure' if 'fail' in line.lower() else 'success',
                'message': line,
                'rawLine': line,
                'fields': {},
                'tags': ['attack'] if attack_type != 'safe' else [],
                'attackType': attack_type if attack_type != 'safe' else None,
                'attackConfidence': confidence if attack_type != 'safe' else None,
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
    ip_pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
    match = re.search(ip_pattern, line)
    return match.group(1) if match else None


@app.post("/parse/file")
async def parse_log_file(
    file: UploadFile = File(...),
    forceType: Optional[str] = Form(None)
):
    """Parse uploaded log file"""
    content = await file.read()
    content_str = content.decode('utf-8', errors='ignore')
    
    # Delegate to parse_logs
    return await parse_logs(content=content_str, forceType=forceType)


@app.post("/parse/chunked")
async def parse_chunked_logs(
    chunks: List[str] = Form(...),
    fileName: Optional[str] = Form(None)
):
    """Parse pre-chunked log content"""
    content = '\n'.join(chunks)
    return await parse_logs(content=content)


@app.get("/health")
async def health():
    return {
        "status": "ok", 
        "ml_enabled": PARSERS_AVAILABLE,
        "parsers_available": PARSERS_AVAILABLE
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

# SOC LLM Direct Model Loading
_soc_llm_model = None
_soc_llm_tokenizer = None
_soc_llm_loaded = False

def load_soc_llm():
    """Load SOC Analyst LLM model directly"""
    global _soc_llm_model, _soc_llm_tokenizer, _soc_llm_loaded
    
    if _soc_llm_loaded:
        return True
    
    if not LLM_AVAILABLE:
        print("WARNING: LLM libraries not available. Install: pip install transformers torch peft")
        return False
    
    try:
        print("Loading SOC Analyst LLM model...")
        model_path = os.path.join(os.path.dirname(__file__), '..', '..', 'soc-analyst-llm', 'models', 'soc-analyst-tinyllama-final')
        
        if not os.path.exists(model_path):
            print(f"Model not found at {model_path}")
            return False
        
        # Load tokenizer
        _soc_llm_tokenizer = AutoTokenizer.from_pretrained(model_path)
        
        # Set padding token if not set
        if _soc_llm_tokenizer.pad_token is None:
            _soc_llm_tokenizer.pad_token = _soc_llm_tokenizer.eos_token
        if _soc_llm_tokenizer.pad_token_id is None:
            _soc_llm_tokenizer.pad_token_id = _soc_llm_tokenizer.eos_token_id
        
        # Determine device
        device = "cuda" if torch.cuda.is_available() else "cpu"
        print(f"Using device: {device}")
        
        # Load base model with GPU support
        global _soc_llm_model
        print("Loading base model...")
        
        device = "cuda" if torch.cuda.is_available() else "cpu"
        print(f"Using device: {device}")
        
        try:
            # Load model
            base_model = AutoModelForCausalLM.from_pretrained(
                "TinyLlama/TinyLlama-1.1B-Chat-v1.0",
                torch_dtype=torch.float16 if device == "cuda" else torch.float32,
                device_map="auto" if device == "cuda" else None,
                low_cpu_mem_usage=True
            )
            
            if device == "cpu":
                base_model = base_model.to("cpu")
            
            # Load LoRA adapters
            print("Loading LoRA adapters...")
            _soc_llm_model = PeftModel.from_pretrained(base_model, model_path)
            
            if device == "cpu":
                _soc_llm_model = _soc_llm_model.to("cpu")
            
            _soc_llm_model.eval()
            
            # Disable gradients
            for param in _soc_llm_model.parameters():
                param.requires_grad = False
            
            _soc_llm_loaded = True
            print(f"[OK] SOC Analyst LLM loaded successfully on {device.upper()}!")
            return True
        except Exception as inner_e:
            print(f"Error during model loading: {inner_e}")
            import traceback
            traceback.print_exc()
            raise
    except Exception as e:
        print(f"Error loading LLM: {e}")
        import traceback
        traceback.print_exc()
        return False

def analyze_log_rule_based(log_entry: str, log_type: str) -> str:
    """Rule-based log analysis as fallback"""
    log_lower = log_entry.lower()
    
    # Check for common attack patterns
    if 'failed password' in log_lower or 'authentication failure' in log_lower:
        failed_count = log_lower.count('failed')
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
    
    if any(x in log_lower for x in ['sql', 'union', 'select', 'drop', 'insert', 'update']):
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
    
    if any(x in log_lower for x in ['sudo', 'privilege', 'escalation', 'root']):
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
    
    if any(x in log_lower for x in ['outbound', 'external', 'exfil', 'transfer']):
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
    """Analyze log using local LLM"""
    global _soc_llm_model, _soc_llm_tokenizer, _soc_llm_loaded
    
    if not _soc_llm_loaded and not load_soc_llm():
        # Fallback to rule-based analysis
        return analyze_log_rule_based(log_entry, log_type)
    
    try:
        with torch.no_grad():
            prompt = f"### Instruction:\nAnalyze this {log_type} log entry for security threats.\n\n### Input:\n{log_entry}\n\n### Response:\n"
            
            inputs = _soc_llm_tokenizer(prompt, return_tensors="pt", truncation=True, max_length=512)
            
            # Move to same device as model
            device = next(_soc_llm_model.parameters()).device
            inputs = {k: v.to(device) for k, v in inputs.items()}
            
            outputs = _soc_llm_model.generate(
                **inputs,
                max_new_tokens=200,
                pad_token_id=_soc_llm_tokenizer.pad_token_id,
                eos_token_id=_soc_llm_tokenizer.eos_token_id,
                do_sample=False,  # Use greedy decoding for stability
                num_beams=1
            )
            
            response = _soc_llm_tokenizer.decode(outputs[0], skip_special_tokens=True)
            # Extract just the response part
            if "### Response:" in response:
                response = response.split("### Response:")[-1].strip()
            
            # Check if response is empty or too short
            if not response or len(response) < 10:
                print(f"Warning: Model returned empty/short response for log analysis, using fallback")
                return analyze_log_rule_based(log_entry, log_type)
            
            return response
    except Exception as e:
        print(f"Error in LLM analysis: {e}")
        # Fallback to rule-based analysis on error
        return analyze_log_rule_based(log_entry, log_type)

def generate_soc_response(message: str) -> str:
    """Generate a SOC analyst response using rule-based fallback"""
    message_lower = message.lower()
    
    # Common security questions and answers
    responses = {
        'brute force': """ALERT: Brute Force Attack

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
        
        'sql injection': """ALERT: SQL Injection (SQLi)

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
        
        'ddos': """ALERT: DDoS Attack (Distributed Denial of Service)

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
        
        'malware': """ALERT: Malware Analysis

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
    """Chat with local LLM"""
    global _soc_llm_model, _soc_llm_tokenizer, _soc_llm_loaded
    
    if not _soc_llm_loaded and not load_soc_llm():
        # Fallback to rule-based responses
        return generate_soc_response(message)
    
    try:
        with torch.no_grad():
            # Build conversation
            prompt = "### Instruction:\nYou are a SOC Analyst AI. Answer the following question about security.\n\n"
            
            # Add context if provided
            for msg in context[-3:]:  # Last 3 messages for context
                role = msg.get('role', 'user')
                content = msg.get('content', '')
                if role == 'user':
                    prompt += f"### Input:\n{content}\n\n"
                else:
                    prompt += f"### Response:\n{content}\n\n"
            
            prompt += f"### Input:\n{message}\n\n### Response:\n"
            
            inputs = _soc_llm_tokenizer(prompt, return_tensors="pt", truncation=True, max_length=512)
            
            # Move to same device as model
            device = next(_soc_llm_model.parameters()).device
            inputs = {k: v.to(device) for k, v in inputs.items()}
            
            outputs = _soc_llm_model.generate(
                **inputs,
                max_new_tokens=300,
                pad_token_id=_soc_llm_tokenizer.pad_token_id,
                eos_token_id=_soc_llm_tokenizer.eos_token_id,
                do_sample=False,  # Use greedy decoding for stability
                num_beams=1
            )
            
            response = _soc_llm_tokenizer.decode(outputs[0], skip_special_tokens=True)
            if "### Response:" in response:
                response = response.split("### Response:")[-1].strip()
            
            # Check if response is empty or too short
            if not response or len(response) < 10:
                print(f"Warning: Model returned empty/short response, using fallback")
                return generate_soc_response(message)
            
            return response
    except Exception as e:
        print(f"Error in LLM chat: {e}")
        # Fallback to rule-based response on error
        return generate_soc_response(message)

@app.post("/soc-analyze", response_model=LogAnalysisResponse)
async def soc_analyze_log(request: LogAnalysisRequest):
    """Analyze a log entry using SOC Analyst LLM"""
    try:
        analysis = analyze_with_llm(request.log_entry, request.log_type)
        
        # Parse attack indicators
        attack_detected = any(keyword in analysis.lower() for keyword in [
            "attack", "threat", "malicious", "suspicious", "breach", "compromise", "brute force"
        ])
        
        severity = "low"
        if "critical" in analysis.lower():
            severity = "critical"
        elif "high" in analysis.lower():
            severity = "high"
        elif "medium" in analysis.lower():
            severity = "medium"
        
        return LogAnalysisResponse(
            analysis=analysis,
            attack_detected=attack_detected,
            severity=severity
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"LLM analysis error: {str(e)}")

@app.post("/soc-chat", response_model=ChatResponse)
async def soc_chat(request: ChatRequest):
    """Chat with SOC Analyst LLM"""
    try:
        response = chat_with_llm(request.message, request.context)
        return ChatResponse(response=response)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Chat error: {str(e)}")

@app.post("/soc-chat", response_model=ChatResponse)
async def soc_chat(request: ChatRequest):
    """Chat with SOC Analyst LLM"""
    if not check_soc_llm():
        raise HTTPException(status_code=503, detail="SOC Analyst LLM not available. Please start the LLM server on port 8000.")
    
    try:
        import requests
        response = requests.post(
            f"{_soc_llm_url}/chat",
            json={"message": request.message, "context": request.context or []},
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            return ChatResponse(response=data.get("response", ""))
        else:
            raise HTTPException(status_code=500, detail="Chat failed")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error calling LLM: {str(e)}")

@app.get("/soc-health")
async def soc_health():
    """Check SOC Analyst LLM health"""
    is_loaded = _soc_llm_loaded or load_soc_llm()
    return {
        "status": "ok" if is_loaded else "loading",
        "llm_loaded": is_loaded,
        "model": "TinyLlama-1.1B-SOC-Analyst (Local)"
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
            "timestamp": datetime.now().isoformat()
        }
        _feedback_storage.append(feedback_entry)
        
        # Optionally save to file
        try:
            feedback_file = os.path.join(os.path.dirname(__file__), 'user_feedback.json')
            with open(feedback_file, 'w') as f:
                json.dump(_feedback_storage, f, indent=2)
        except:
            pass  # File save is optional
        
        return FeedbackResponse(
            status="success",
            message="Feedback received and saved for future training!",
            training_examples_count=len(_feedback_storage)
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error saving feedback: {str(e)}")

@app.post("/soc-train", response_model=TrainResponse)
async def train_on_feedback(request: TrainRequest = None):
    """Train the model on accumulated feedback"""
    try:
        if len(_feedback_storage) == 0:
            return TrainResponse(
                status="skipped",
                message="No feedback available to train on."
            )
        
        epochs = request.epochs if request else 1
        
        # Save feedback as training data
        training_data = []
        for fb in _feedback_storage:
            if fb['rating'] == 5 or (fb['rating'] == 1 and fb.get('feedback_text')):
                example = {
                    "instruction": fb['original_prompt'],
                    "input": fb.get('log_context', ''),
                    "output": fb.get('feedback_text') if fb['rating'] == 1 and fb.get('feedback_text') else fb['llm_response']
                }
                training_data.append(example)
        
        # Save to training data file
        training_file = os.path.join(os.path.dirname(__file__), 'feedback_training_data.json')
        with open(training_file, 'w') as f:
            json.dump(training_data, f, indent=2)
        
        return TrainResponse(
            status="success",
            message=f"Training data prepared with {len(training_data)} examples from {len(_feedback_storage)} feedback entries. Run 'python continue_training.py' to retrain the model."
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error preparing training: {str(e)}")

@app.get("/soc-feedback/stats")
async def get_feedback_stats():
    """Get feedback statistics"""
    likes = sum(1 for f in _feedback_storage if f.get('rating') == 5)
    dislikes = sum(1 for f in _feedback_storage if f.get('rating') == 1)
    
    return {
        "total_feedback": len(_feedback_storage),
        "likes": likes,
        "dislikes": dislikes,
        "pending_training": len(_feedback_storage)
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8788)
