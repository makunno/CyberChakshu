// LogDetector - ISEA-style log detection with precompiled regex patterns

export class LogDetector {
  private static readonly SAMPLE_LINES = 50;
  private static readonly CANDIDATE_SAMPLE_LINES = 10;

  // ===========================
  // Precompiled Regex Patterns
  // ===========================
  
  private static readonly EXPRESS_JSON_RE = /^\{/;
  private static readonly APACHE_RE = /\S+ - - \[.*?\] ".*?" \d+ \d+/;
  private static readonly LARAVEL_RE = /\[\d{4}-\d{2}-\d{2} .*?\] \w+\.\w+:/;
  private static readonly NODE_RE = /\w+\s+\S+\s+\d+\s+\d+ms/;
  private static readonly DJANGO_RE = /\[.*?\] "\w+\s+\S+"\s+\d+/;
  private static readonly FLASK_RE = /(?:GET|POST|PUT|DELETE)\s+\S+\s+\d+/;
  private static readonly RAILS_RE = /Processing by/;
  private static readonly GUNICORN_RE = /\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}.*\] \[\d+\] \[(?:INFO|ERROR|WARNING)\]/;
  private static readonly UVICORN_RE = /INFO:\s+.* - "\w+ .* HTTP\/\d\.\d" \d{3}/;
  private static readonly NGINX_RE = /\S+ - \S+ \[.*?\] ".*?" \d+ \d+/;
  private static readonly CADDY_RE = /^(?:\d{1,3}\.){3}\d{1,3}\s+-\s+-\s+\[INFO\]\s+http\.log:\s+handled\s+(?:GET|POST|PUT|DELETE)\s+\S+\s+\d{3}$/;
  private static readonly IIS_RE = /^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+\d{1,3}(?:\.\d{1,3}){3}\s+(?:GET|POST|PUT|DELETE)\s+\/\S*\s+.*\s+\d{3}\s*/;
  private static readonly POSTFIX_RE = /^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+postfix\/(?:smtpd|smtp|cleanup|qmgr)\[\d+\]:\s+.+$/;
  private static readonly SENDMAIL_RE = /^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+sendmail\[\d+\]:\s+.+$/;
  private static readonly EXIM_RE = /^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+[A-Z0-9]{6,}\s+(?:<=|=>|\*\*)\s+\S+.*$/;
  private static readonly DOVECOT_RE = /^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+dovecot:\s+(?:imap|pop3)-login:\s+.+$/;
  private static readonly COURIER_RE = /^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+courier(?:imap|pop3):\s+.+$/;
  private static readonly EXCHANGE_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z,SMTP(?:Receive|Send|Deliver),.+$/;
  private static readonly AMAVIS_RE = /^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+amavis\[\d+\]:\s+.+$/;
  private static readonly SPAMASSASSIN_RE = /^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+spamd\[\d+\]:\s+.+$/;
  private static readonly MAILSCANNER_RE = /^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+MailScanner\[\d+\]:\s+.+$/;
  private static readonly SMTP_GENERIC_RE = /^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+SMTP\s+(?:connect|disconnect|from=|to=).+$/;
  private static readonly WINDOWS_FW_RE = /^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+(?:ALLOW|DROP|BLOCK)\s+(?:TCP|UDP|ICMP)\s+(?:\d{1,3}\.){3}\d{1,3}\s+(?:\d{1,3}\.){3}\d{1,3}\s+\d+\s+\d+.*$/;
  private static readonly IPTABLES_RE = /^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+kernel:\s+IPTABLES-(?:DROP|ACCEPT):\s+IN=\S*\s+OUT=\S*\s+.*SRC=(?:\d{1,3}\.){3}\d{1,3}\s+DST=(?:\d{1,3}\.){3}\d{1,3}.*PROTO=(?:TCP|UDP|ICMP).*$/;
  private static readonly UFW_RE = /^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+ufw\[\d+\]:\s+\[UFW (?:ALLOW|BLOCK)\]\s+IN=\S*\s+OUT=\S*\s+SRC=(?:\d{1,3}\.){3}\d{1,3}\s+DST=(?:\d{1,3}\.){3}\d{1,3}.*$/;
  private static readonly NFTABLES_RE = /^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+kernel:\s+nftables:\s+rule\s+(?:accept|drop|reject)\s+.*(?:tcp|udp|icmp).*$/;
  private static readonly FIREWALLD_RE = /^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+firewalld:\s+(?:INFO|WARNING|ERROR):\s+.*$/;
  private static readonly MACOS_PF_RE = /^\d{2}:\d{2}:\d{2}\.\d+\s+rule\s+\d+\/\d+\s+\((?:match)\):\s+(?:block|pass)\s+(?:in|out)\s+on\s+\S+:\s+(?:\d{1,3}\.){3}\d{1,3}\.\d+\s+>\s+(?:\d{1,3}\.){3}\d{1,3}\.\d+.*$/;
  private static readonly MACOS_APP_FW_RE = /^Firewall:\s+(?:Blocked|Allowed)\s+(?:incoming|outgoing)\s+connection from\s+(?:\d{1,3}\.){3}\d{1,3}\s+to\s+app\s+\S+.*$/;
  private static readonly PALO_ALTO_RE = /^\d{4}\/\d{2}\/\d{2}\s+\d{2}:\d{2}:\d{2}\s+(?:allow|deny|drop)\s+(?:tcp|udp|icmp)\s+(?:\d{1,3}\.){3}\d{1,3}\s+(?:\d{1,3}\.){3}\d{1,3}\s+rule=\S+.*$/;
  private static readonly FORTIGATE_RE = /^date=\d{4}-\d{2}-\d{2}\s+time=\d{2}:\d{2}:\d{2}\s+action=(?:allow|deny)\s+srcip=(?:\d{1,3}\.){3}\d{1,3}\s+dstip=(?:\d{1,3}\.){3}\d{1,3}.*$/;
  private static readonly CISCO_ASA_RE = /^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+%ASA-\d-\d+:\s+access-list\s+\S+\s+(?:denied|permitted)\s+(?:tcp|udp|icmp)\s+\S+\/(?:\d{1,3}\.){3}\d{1,3}\s+to\s+\S+\/(?:\d{1,3}\.){3}\d{1,3}.*$/;
  private static readonly CHECKPOINT_RE = /^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+(?:accept|drop|reject)\s+(?:TCP|UDP|ICMP)\s+src=(?:\d{1,3}\.){3}\d{1,3}\s+dst=(?:\d{1,3}\.){3}\d{1,3}\s+rule=\S+.*$/;
  private static readonly AWS_VPC_RE = /^(\d+)\s+(\d+)\s+(?:eni-\S+)\s+(?:(?:\d{1,3}\.){3}\d{1,3})\s+(?:(?:\d{1,3}\.){3}\d{1,3})\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(?:ACCEPT|REJECT)\s+(\S+)$/;
  private static readonly AZURE_NSG_RE = /^\{(?=.*"time"\s*:\s*"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z")(?=.*"properties"\s*:\s*\{)(?=.*"flows"\s*:\s*\[)(?=.*"flowTuples"\s*:\s*\[).*\}$/;
  private static readonly GCP_VPC_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\s+(?:allow|deny)\s+(?:tcp|udp|icmp)\s+(?:\d{1,3}\.){3}\d{1,3}:\d+\s+(?:\d{1,3}\.){3}\d{1,3}:\d+.*$/;
  private static readonly APPLICATION_JSON_RE = /^\[\[.*\]\]$/;
  private static readonly MOODLE_LMS_RE = /^\[\["19(?:\\\/)?\d{2}(?:\\\/)?\d{2},\s+\d{2}:\d{2}"/;
  private static readonly APACHE_ERROR_RES = [
    /^\[.*?\] \[.*?:.*?\] \[pid \d+:tid \d+\] .*/,
    /^\[.*?\] \[.*?:.*?\] \[pid \d+\] .*/,
    /^\[.*?\] \[.*?:.*?\] \[pid \d+:tid \d+\] \[client .*?\] .*/,
  ];
  private static readonly MYSQL_ERROR_RE = /(\S+Z)\s+(\d+)\s+\[ERROR\]\s+\[MY-(\d+)\]\s+\[Server\]\s+(.*)/;
  private static readonly MYSQL_QUERY_RE = /(\S+Z)\s+(\d+)\s+Query\s+(.*);/;
  private static readonly MYSQL_SLOW_RE = /^# Time:/;
  private static readonly POSTGRES_ERROR_RE = /^(?:\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?\s+\w+)\s+\[(\d+)\]\s+(?:\S+@\S+\s+)?(?:ERROR|FATAL):\s+([0-9A-Z]{5}):\s+(.*)$/;
  private static readonly POSTGRES_AUTH_RE = /(\S+)\s+(\S+)\s+\[(\d+)\].*user=(\w+)\s+database=(\w+)/;
  private static readonly POSTGRES_STATEMENT_RE = /(\S+)\s+(\S+)\s+\[(\d+)\]\s+STATEMENT:\s+(.*);/;
  private static readonly ORACLE_ALERT_RE = /^[A-Za-z]{3}\s+[A-Za-z]{3}\s+\d{2}\s+\d{2}:\d{2}:\d{2}\s+\d{4}\s+(?:TIMESTAMP|Thread|SID|Instance|Network|Error|ORA-)/;
  private static readonly ORACLE_LISTENER_RE = /(.*?)\s+\*.*SERVICE_NAME=(\w+).*PROTOCOL=(\w+).*HOST=(\d+\.\d+\.\d+\.\d+).*PORT=(\d+).*\*\s+(\d+)/;
  private static readonly ORACLE_AUDIT_RE = /^Audit record generated/;
  private static readonly SQLSERVER_ERROR_RE = /(.*?) Server Error: (\d+), Severity: (\d+), State: (\d+)/;
  private static readonly SQLSERVER_AUDIT_RE = /action_id=(\w+).*name=(\w+).*database_name=(\w+).*statement=(.*)/;
  private static readonly SQLSERVER_TRANSACTION_RE = /\((\d+):(\d+):(\d+)\).*Operation:\s+(.*)/;
  private static readonly MONGODB_SERVER_RE = /^\{.*"t".*:.*"s".*:.*"c".*:.*"msg".*.*\}$/;
  private static readonly MONGODB_AUDIT_RE = /^\{.*"atype".*:.*"ts".*.*\}$/;
  private static readonly LINUX_SSHD_FAILED_RE = /^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(?:sshd)\[\d+\]:\s+Failed\s+\w+\s+for\s+(?:invalid\s+user\s+)?(\S+)\s+from\s+(\d{1,3}(?:\.\d{1,3}){3})\s+port\s+(\d+)/;
  private static readonly LINUX_SSHD_ACCEPTED_RE = /^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(?:sshd)\[\d+\]:\s+Accepted\s+\w+\s+for\s+(\S+)\s+from\s+(\d{1,3}(?:\.\d{1,3}){3})\s+port\s+(\d+)/;
  private static readonly LINUX_SYSLOG_RE = /(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([\w\-\/]+)\[(\d+)\]:\s+(.*)/;
  private static readonly LINUX_SYSTEMD_RE = /(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+systemd\[(\d+)\]:\s+(.*)/;
  private static readonly LINUX_KERNEL_RE = /(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+kernel:\s+(.*)/;
  private static readonly LINUX_AUDIT_RE = /type=(\w+)\s+msg=audit\((\d+)\.\d+:(\d+)\):\s*(.*)/;
  private static readonly LINUX_PACKAGE_RE = /(\d{4}-\d{2}-\d{2})\s+(.*)/;
  private static readonly WINDOWS_TEXT_RE = /(\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2}),\s*([^,]+),\s*([^,]+),\s*(\d+),\s*(.*)/;
  private static readonly WINDOWS_APPLICATION_RE = /^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+Application\s+\d+\s+(INFO|WARNING|ERROR|CRITICAL)/;
  private static readonly WINDOWS_SYSTEM_RE = /^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+System\s+\d+\s+(INFO|WARNING|ERROR|CRITICAL)/;
  private static readonly WINDOWS_SECURITY_RE = /^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+Security\s+\d+\s+(INFO|WARNING|ERROR|CRITICAL)/;
  private static readonly WINDOWS_SETUP_RE = /^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+Setup\s+\d+\s+(INFO|WARNING|ERROR|CRITICAL)/;
  private static readonly WINDOWS_FORWARDED_RE = /^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+ForwardedEvents\s+\d+\s+(INFO|WARNING|ERROR|CRITICAL)/;
  // Windows Event Viewer TXT export format: Keywords\tDate Time\tSource\tEvent ID\tTask\t"Description"
  // Simplified patterns for reliable detection
  private static readonly WINDOWS_EVENTVIEWER_RE = /^(Audit (?:Success|Failure|Error|Warning)|Success|Failure|Error|Warning) \d{2}-\d{2}-\d{4} \d{2}:\d{2}:\d{2} /;
  private static readonly WINDOWS_EVENTVIEWER_TAB_RE = /^(Audit (?:Success|Failure|Error|Warning)|Success|Failure|Error|Warning)\t\d{2}-\d{2}-\d{4} \d{2}:\d{2}:\d{2}\t/;
  // Windows Application TXT format: Level\tDate Time\tSource\tEvent ID\tTask\tMessage
  private static readonly WINDOWS_APPLICATION_TXT_RE = /^(Information|Warning|Error|Critical)\t\d{2}-\d{2}-\d{4} \d{2}:\d{2}:\d{2}\t/;
  // Windows Application CSV format: Level,Date Time,Source,Event ID,Task,Message
  private static readonly WINDOWS_APPLICATION_CSV_RE = /^(Information|Warning|Error|Critical),\d{2}-\d{2}-\d{4} \d{2}:\d{2}:\d{2},[^,]+,\d+,[^,]+,/;
  // Windows Event Viewer CSV format: Keywords,Date Time,Source,Event ID,Task,Message
  private static readonly WINDOWS_EVENTVIEWER_CSV_RE = /^(Audit (?:Success|Failure|Error|Warning)),\d{2}-\d{2}-\d{4} \d{2}:\d{2}:\d{2},[^,]+,\d+,[^,]+,/;
  private static readonly JSON_FTP_RE = /^\[\s*\{\s*"timestamp":/;
  private static readonly FILEZILLA_RE = /^\(\d+\).*?(\d{1,2})\/(\d{1,2})\/(\d{4})\s+(\d{1,2}:\d{2}:\d{2})\s*(?:AM|PM)?\s*-\s+.*?\s+\(([\d\.]+)\)\s*(?:>\s*)?(\d{3})/;
  private static readonly IIS_FTP_RE = /(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})\s+([\d\.]+)\s+([\w\-]+)\s+[\d\.]+\s+\d+\s+(\w+)\s+([\S]*)\s+(\d+)/;
  private static readonly XFERLOG_RE = /^(Sun|Mon|Tue|Wed|Thu|Fri|Sat) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) .* \d{4} .* ftp .* [*] c$/;
  private static readonly FASTAPI_JSON_RE = /^\{"time":\s*".*?",\s*"framework":\s*"FastAPI"/;
  private static readonly PHP_FPM_RE = /\[\d{2}-[A-Za-z]{3}-\d{4}\s+\d{2}:\d{2}:\d{2}\]\s+(?:NOTICE|WARNING|ERROR):/;
  private static readonly HAPROXY_RE = /^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+haproxy\[\d+\]:\s+(?:GET|POST|PUT|DELETE)\s+\S+\s+\d{3}$/;
  private static readonly SPRING_BOOT_RE = /^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+\s+(?:INFO|WARN|ERROR|DEBUG)\s+\S+\s+-\s+(?:GET|POST|PUT|DELETE|PATCH)\s+\S+\s+\d{3}$/;
  private static readonly ASPNET_CORE_RE = /^(?:info|warn|error|debug):\s+Microsoft\.AspNetCore/i;
  private static readonly CLOUDFLARE_RE = /^\{.*"timestamp".*"?\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.*".*\}?$/;
  private static readonly AWS_CLOUDTRAIL_RE = /^\{.*"eventTime".*"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z".*"eventSource".*"aws\..*".*\}$/;
  private static readonly AWS_GUARDDUTY_RE = /^\{.*"detectorId".*"createdAt".*"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z".*"severity".*\d+.*\}$/;
  private static readonly AZURE_ACTIVITY_RE = /^\{.*"time".*"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z".*"operationName".*".*".*"category".*".*"\}.*$/;
  private static readonly GCP_AUDIT_RE = /^\{.*"protoPayload".*".*@googleapis\.com".*"methodName".*"audit_log_timestamp".*"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z".*\}$/;
  private static readonly KUBERNETES_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{9}Z\s+\w+\s+\w+\s+\w+\[\d+\]:\s+.*$/;
  private static readonly DOCKER_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+\w\s+\w+\s+\w+\[\d+\]:\s+.*$/;
  private static readonly ELASTICSEARCH_RE = /\[\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2},\d+\]\[(\w+)\]\[(\w+)\]\s+.*$/;
  private static readonly REDIS_RE = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} \w+(?: #\d+)?(?: \*)?.*$/;
  private static readonly RABBITMQ_RE = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} \[\w+\] \(<.*>@.*\)$/;
  private static readonly KAFKA_RE = /^\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d+\]\s+(?:INFO|WARN|ERROR)\s+\[\w+,\w+\]\s+.*$/;
  private static readonly ZOOKEEPER_RE = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} \d+\s+\w+\s+\[\w+\]\s+.*$/;
  private static readonly NGINX_ERROR_RE = /^\d{4}\/\d{2}\/\d{2}\s+\d{2}:\d{2}:\d{2}\s+\[\w+\]\s+\d+#\d+:\s+\*?\d+\s+.*$/;
  private static readonly SQUID_RE = /^\d{10}\s+\d+\s+\d+\s+\w+\s+\d+\s+\w+\s+\d+\s+\w+\s+(?:\d{1,3}\.){3}\d{1,3}\s+\w+\/\w+\/\w+\s+.*$/;
  private static readonly SURICATA_RE = /^\[\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+\]\s+\[\w+\]\s+\[\w+\]\s+\[\*\*\].*$/;
  private static readonly ZEEK_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z\s+\w+\s+\w+\s+.*$/;
  private static readonly OSSEC_RE = /^\d{4}\/\d{2}\/\d{2}\s+\d{2}:\d{2}:\d{2}\s+\w+\s+\w+\s+(?:\w+:)?\w+\s+\[\d+\]:\s+.*$/;
  private static readonly FAIL2BAN_RE = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d+\s+fail2ban\.(?:filter|actions)\[\d+\]:\s+WARNING\s+\[.*\]\s+Ban\s+\d{1,3}(?:\.\d{1,3}){3}$/;
  private static readonly AUTH0_RE = /^\{.*"date".*"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z".*"type".*".*".*"client_id".*".*"\}.*$/;
  private static readonly APACHE_COMBINED_RE = /\S+ - - \[.*?\] ".*?" \d+ \d+ "(?:.*?)" "(?:.*?)"/;
  private static readonly DHCP_RE = /^(\w{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(\S+)\s+(.*)/;
  private static readonly DNS_RE = /^(\w{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(\S+)\s+(.*)/;
  private static readonly PROXY_RE = /^(\w{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(\S+)\s+(.*)/;
  private static readonly AIOHTTP_RE = /^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+\s+(?:INFO|WARNING|ERROR|DEBUG).*"(?:GET|POST|PUT|DELETE)\s+\S+\s+\d{3}"/;
  private static readonly STARLETTE_RE = /^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+\s+(?:INFO|WARNING|ERROR|DEBUG).*"(?:GET|POST|PUT|DELETE|PATCH)\s+\S+\s+\d{3}"/;

  // ===========================
  // is_*() Methods for Detection
  // ===========================

  static isExpressJson(line: string): boolean { return !!LogDetector.EXPRESS_JSON_RE.test(line); }
  static isApache(line: string): boolean { return !!LogDetector.APACHE_RE.test(line); }
  static isLaravel(line: string): boolean { return !!LogDetector.LARAVEL_RE.test(line); }
  static isNode(line: string): boolean { return !!LogDetector.NODE_RE.test(line); }
  static isDjango(line: string): boolean { return !!LogDetector.DJANGO_RE.test(line); }
  static isFlask(line: string): boolean { return !!LogDetector.FLASK_RE.test(line); }
  static isRails(line: string): boolean { return line.includes("Processing by") || line.includes("Started GET"); }
  static isGunicorn(line: string): boolean { return !!LogDetector.GUNICORN_RE.test(line); }
  static isUvicorn(line: string): boolean { return !!LogDetector.UVICORN_RE.test(line); }
  static isPhpFpm(line: string): boolean { return line.includes("[pool ") || !!LogDetector.PHP_FPM_RE.test(line); }
  static isNginx(line: string): boolean { return !!LogDetector.NGINX_RE.test(line); }
  static isCaddy(line: string): boolean { return !!LogDetector.CADDY_RE.test(line); }
  static isHaproxy(line: string): boolean { return !!LogDetector.HAPROXY_RE.test(line); }
  static isSpringBoot(line: string): boolean { return !!LogDetector.SPRING_BOOT_RE.test(line); }
  static isAspnetCore(line: string): boolean { return !!LogDetector.ASPNET_CORE_RE.test(line); }
  static isIis(line: string): boolean { return !!LogDetector.IIS_RE.test(line); }
  static isPostfix(line: string): boolean { return !!LogDetector.POSTFIX_RE.test(line); }
  static isSendmail(line: string): boolean { return !!LogDetector.SENDMAIL_RE.test(line); }
  static isExim(line: string): boolean { return !!LogDetector.EXIM_RE.test(line); }
  static isDovecot(line: string): boolean { return !!LogDetector.DOVECOT_RE.test(line); }
  static isCourier(line: string): boolean { return !!LogDetector.COURIER_RE.test(line); }
  static isExchange(line: string): boolean { return !!LogDetector.EXCHANGE_RE.test(line); }
  static isAmavis(line: string): boolean { return !!LogDetector.AMAVIS_RE.test(line); }
  static isSpamassassin(line: string): boolean { return !!LogDetector.SPAMASSASSIN_RE.test(line); }
  static isMailscanner(line: string): boolean { return !!LogDetector.MAILSCANNER_RE.test(line); }
  static isSmtpGeneric(line: string): boolean { return !!LogDetector.SMTP_GENERIC_RE.test(line); }
  static isWindowsFw(line: string): boolean { return !!LogDetector.WINDOWS_FW_RE.test(line); }
  static isIptables(line: string): boolean { return !!LogDetector.IPTABLES_RE.test(line); }
  static isUfw(line: string): boolean { return !!LogDetector.UFW_RE.test(line); }
  static isNftables(line: string): boolean { return !!LogDetector.NFTABLES_RE.test(line); }
  static isFirewalld(line: string): boolean { return !!LogDetector.FIREWALLD_RE.test(line); }
  static isMacosPf(line: string): boolean { return !!LogDetector.MACOS_PF_RE.test(line); }
  static isMacosAppFw(line: string): boolean { return !!LogDetector.MACOS_APP_FW_RE.test(line); }
  static isPaloAlto(line: string): boolean { return !!LogDetector.PALO_ALTO_RE.test(line); }
  static isFortigate(line: string): boolean { return !!LogDetector.FORTIGATE_RE.test(line); }
  static isCiscoAsa(line: string): boolean { return !!LogDetector.CISCO_ASA_RE.test(line); }
  static isCheckpoint(line: string): boolean { return !!LogDetector.CHECKPOINT_RE.test(line); }
  static isAwsVpc(line: string): boolean { return !!LogDetector.AWS_VPC_RE.test(line); }
  static isAzureNsg(line: string): boolean { return !!LogDetector.AZURE_NSG_RE.test(line); }
  static isGcpVpc(line: string): boolean { return !!LogDetector.GCP_VPC_RE.test(line); }
  static isDiskTraffic(line: string): boolean { return line.includes('type="traffic"'); }
  static isApplicationJson(line: string): boolean {
    // Check pattern without full JSON.parse for large files
    return LogDetector.APPLICATION_JSON_RE.test(line.slice(0, 100));
  }
  static isApacheError(line: string): boolean {
    return LogDetector.APACHE_ERROR_RES.some(pattern => pattern.test(line));
  }
  static isMysqlError(line: string): boolean { return !!LogDetector.MYSQL_ERROR_RE.test(line); }
  static isMysqlQuery(line: string): boolean { return !!LogDetector.MYSQL_QUERY_RE.test(line); }
  static isMysqlSlow(line: string): boolean { return !!LogDetector.MYSQL_SLOW_RE.test(line); }
  static isPostgresError(line: string): boolean { return !!LogDetector.POSTGRES_ERROR_RE.test(line); }
  static isPostgresAuth(line: string): boolean { return !!LogDetector.POSTGRES_AUTH_RE.test(line); }
  static isPostgresStatement(line: string): boolean { return !!LogDetector.POSTGRES_STATEMENT_RE.test(line); }
  static isOracleAlert(line: string): boolean { return !!LogDetector.ORACLE_ALERT_RE.test(line); }
  static isOracleListener(line: string): boolean { return !!LogDetector.ORACLE_LISTENER_RE.test(line); }
  static isOracleAudit(line: string): boolean { return !!LogDetector.ORACLE_AUDIT_RE.test(line); }
  static isSqlserverError(line: string): boolean { return !!LogDetector.SQLSERVER_ERROR_RE.test(line); }
  static isSqlserverAudit(line: string): boolean { return !!LogDetector.SQLSERVER_AUDIT_RE.test(line); }
  static isSqlserverTransaction(line: string): boolean { return !!LogDetector.SQLSERVER_TRANSACTION_RE.test(line); }
  static isMongodbServer(line: string): boolean {
    try {
      JSON.parse(line);
      return true;
    } catch {
      return false;
    }
  }
  static isMongodbAudit(line: string): boolean {
    try {
      const j = JSON.parse(line);
      return "atype" in j && "ts" in j;
    } catch {
      return false;
    }
  }
  static isLinuxSshdFailed(line: string): boolean { return !!LogDetector.LINUX_SSHD_FAILED_RE.test(line); }
  static isLinuxSshdAccepted(line: string): boolean { return !!LogDetector.LINUX_SSHD_ACCEPTED_RE.test(line); }
  static isLinuxSyslog(line: string): boolean { return !!LogDetector.LINUX_SYSLOG_RE.test(line); }
  static isLinuxSystemd(line: string): boolean { return !!LogDetector.LINUX_SYSTEMD_RE.test(line); }
  static isLinuxKernel(line: string): boolean { return !!LogDetector.LINUX_KERNEL_RE.test(line); }
  static isLinuxAudit(line: string): boolean { return !!LogDetector.LINUX_AUDIT_RE.test(line); }
  static isLinuxPackage(line: string): boolean { return !!LogDetector.LINUX_PACKAGE_RE.test(line); }
  static isWindowsText(line: string): boolean { return !!LogDetector.WINDOWS_TEXT_RE.test(line); }
  static isWindowsApplication(line: string): boolean { return !!LogDetector.WINDOWS_APPLICATION_RE.test(line); }
  static isWindowsSystem(line: string): boolean { return !!LogDetector.WINDOWS_SYSTEM_RE.test(line); }
  static isWindowsSecurity(line: string): boolean { return !!LogDetector.WINDOWS_SECURITY_RE.test(line); }
  static isWindowsSetup(line: string): boolean { return !!LogDetector.WINDOWS_SETUP_RE.test(line); }
  static isWindowsForwarded(line: string): boolean { return !!LogDetector.WINDOWS_FORWARDED_RE.test(line); }
  static isWindowsEventViewer(line: string): boolean {
    // Check for tab-separated format first (most reliable)
    if (LogDetector.WINDOWS_EVENTVIEWER_TAB_RE.test(line)) {
      return true;
    }
    // Also check for space-separated format (some exports use spaces instead of tabs)
    if (LogDetector.WINDOWS_EVENTVIEWER_RE.test(line)) {
      return true;
    }
    // Fallback: check for characteristic patterns
    if (line.includes('Microsoft-Windows-') || line.includes('Security-Auditing')) {
      return /^(Audit|Success|Failure|Error|Warning)\s+\d{2}-\d{2}-\d{4}/.test(line);
    }
    return false;
  }
  static isWindowsApplicationTXT(line: string): boolean {
    return !!LogDetector.WINDOWS_APPLICATION_TXT_RE.test(line);
  }
  static isWindowsApplicationCSV(line: string): boolean {
    // Check for CSV format with Level or Keywords at start
    if (LogDetector.WINDOWS_APPLICATION_CSV_RE.test(line)) return true;
    if (LogDetector.WINDOWS_EVENTVIEWER_CSV_RE.test(line)) return true;
    // Also check for header patterns
    if (line.startsWith('Level,') || line.startsWith('Keywords,')) return true;
    return false;
  }
  static isJsonFTPLogs(line: string): boolean { return !!LogDetector.JSON_FTP_RE.test(line); }
  static isFilezilla(line: string): boolean { return !!LogDetector.FILEZILLA_RE.test(line); }
  static isIisFtp(line: string): boolean { return !!LogDetector.IIS_FTP_RE.test(line); }
  static isXferlog(line: string): boolean { return !!LogDetector.XFERLOG_RE.test(line); }
  static isFastapiJson(line: string): boolean { return !!LogDetector.FASTAPI_JSON_RE.test(line); }
  static isMoodleLms(line: string): boolean {
    return line.startsWith('[[') && LogDetector.MOODLE_LMS_RE.test(line.slice(0, 50));
  }
  static isCloudflare(line: string): boolean { return !!LogDetector.CLOUDFLARE_RE.test(line); }
  static isAwsCloudtrail(line: string): boolean { return !!LogDetector.AWS_CLOUDTRAIL_RE.test(line); }
  static isAwsGuardduty(line: string): boolean { return !!LogDetector.AWS_GUARDDUTY_RE.test(line); }
  static isAzureActivity(line: string): boolean { return !!LogDetector.AZURE_ACTIVITY_RE.test(line); }
  static isGcpAudit(line: string): boolean { return !!LogDetector.GCP_AUDIT_RE.test(line); }
  static isKubernetes(line: string): boolean { return !!LogDetector.KUBERNETES_RE.test(line); }
  static isDocker(line: string): boolean { return !!LogDetector.DOCKER_RE.test(line); }
  static isElasticsearch(line: string): boolean { return !!LogDetector.ELASTICSEARCH_RE.test(line); }
  static isRedis(line: string): boolean { return !!LogDetector.REDIS_RE.test(line); }
  static isRabbitmq(line: string): boolean { return !!LogDetector.RABBITMQ_RE.test(line); }
  static isKafka(line: string): boolean { return !!LogDetector.KAFKA_RE.test(line); }
  static isZookeeper(line: string): boolean { return !!LogDetector.ZOOKEEPER_RE.test(line); }
  static isNginxError(line: string): boolean { return !!LogDetector.NGINX_ERROR_RE.test(line); }
  static isSquid(line: string): boolean { return !!LogDetector.SQUID_RE.test(line); }
  static isSuricata(line: string): boolean { return !!LogDetector.SURICATA_RE.test(line); }
  static isZeek(line: string): boolean { return !!LogDetector.ZEEK_RE.test(line); }
  static isOssec(line: string): boolean { return !!LogDetector.OSSEC_RE.test(line); }
  static isFail2ban(line: string): boolean { return !!LogDetector.FAIL2BAN_RE.test(line); }
  static isAuth0(line: string): boolean { return !!LogDetector.AUTH0_RE.test(line); }
  static isApacheCombined(line: string): boolean { return !!LogDetector.APACHE_COMBINED_RE.test(line); }
  static isDhcp(line: string): boolean {
    const match = line.match(LogDetector.DHCP_RE);
    if (!match) return false;
    const serviceLine = match[4];
    return /dhcpd?|dhclient/i.test(serviceLine);
  }
  static isDns(line: string): boolean {
    const match = line.match(LogDetector.DNS_RE);
    if (!match) return false;
    const serviceLine = match[4];
    return /named|bind|dnsmasq|unbound/i.test(serviceLine);
  }
  static isProxy(line: string): boolean {
    const match = line.match(LogDetector.PROXY_RE);
    if (!match) return false;
    const serviceLine = match[4];
    return /squid|haproxy|nginx|microsocks/i.test(serviceLine);
  }
  static isAiohttp(line: string): boolean { return !!LogDetector.AIOHTTP_RE.test(line); }
  static isStarlette(line: string): boolean { return !!LogDetector.STARLETTE_RE.test(line); }

  // ===========================
  // Priority-based Check Functions
  // ===========================

  private static getPriorityOrder(): Array<[string, (line: string) => boolean]> {
    return [
      ["Apache", LogDetector.isApache],
      ["Apache Error", LogDetector.isApacheError],
      ["Django", LogDetector.isDjango],
      ["Flask", LogDetector.isFlask],
      ["Node.js", LogDetector.isNode],
      ["Express.js", LogDetector.isExpressJson],
      ["FastAPI", LogDetector.isFastapiJson],
      ["Laravel", LogDetector.isLaravel],
      ["Ruby on Rails", LogDetector.isRails],
      ["Gunicorn", LogDetector.isGunicorn],
      ["Uvicorn", LogDetector.isUvicorn],
      ["PHP-FPM", LogDetector.isPhpFpm],
      ["NGINX", LogDetector.isNginx],
      ["Caddy", LogDetector.isCaddy],
      ["HAProxy", LogDetector.isHaproxy],
      ["Spring Boot", LogDetector.isSpringBoot],
      ["ASP.NET Core", LogDetector.isAspnetCore],
      ["IIS", LogDetector.isIis],
      ["Postfix", LogDetector.isPostfix],
      ["Sendmail", LogDetector.isSendmail],
      ["Exim", LogDetector.isExim],
      ["Dovecot", LogDetector.isDovecot],
      ["Courier", LogDetector.isCourier],
      ["Microsoft Exchange", LogDetector.isExchange],
      ["SMTP Server", LogDetector.isSmtpGeneric],
      ["Amavis", LogDetector.isAmavis],
      ["SpamAssassin", LogDetector.isSpamassassin],
      ["MailScanner", LogDetector.isMailscanner],
      ["Windows Firewall", LogDetector.isWindowsFw],
      ["iptables", LogDetector.isIptables],
      ["UFW", LogDetector.isUfw],
      ["nftables", LogDetector.isNftables],
      ["firewalld", LogDetector.isFirewalld],
      ["macOS PF", LogDetector.isMacosPf],
      ["macOS App Firewall", LogDetector.isMacosAppFw],
      ["Palo Alto Firewall", LogDetector.isPaloAlto],
      ["FortiGate", LogDetector.isFortigate],
      ["Cisco ASA", LogDetector.isCiscoAsa],
      ["Check Point Firewall", LogDetector.isCheckpoint],
      ["AWS VPC Flow Logs", LogDetector.isAwsVpc],
      ["Azure NSG Flow Logs", LogDetector.isAzureNsg],
      ["GCP VPC Firewall", LogDetector.isGcpVpc],
      ["Disk Traffic", LogDetector.isDiskTraffic],
      ["Moodle LMS", LogDetector.isMoodleLms],
      ["Application Logs JSON", LogDetector.isApplicationJson],
      ["MySQL Error", LogDetector.isMysqlError],
      ["MySQL Query", LogDetector.isMysqlQuery],
      ["MySQL Slow Query", LogDetector.isMysqlSlow],
      ["PostgreSQL Error", LogDetector.isPostgresError],
      ["PostgreSQL Auth", LogDetector.isPostgresAuth],
      ["PostgreSQL Statement", LogDetector.isPostgresStatement],
      ["Oracle Alert", LogDetector.isOracleAlert],
      ["Oracle Listener", LogDetector.isOracleListener],
      ["Oracle Audit", LogDetector.isOracleAudit],
      ["SQL Server Error", LogDetector.isSqlserverError],
      ["SQL Server Audit", LogDetector.isSqlserverAudit],
      ["SQL Server Transaction", LogDetector.isSqlserverTransaction],
      ["MongoDB Server", LogDetector.isMongodbServer],
      ["MongoDB Audit", LogDetector.isMongodbAudit],
      ["Linux SSHD Failed", LogDetector.isLinuxSshdFailed],
      ["Linux SSHD Accepted", LogDetector.isLinuxSshdAccepted],
      ["Linux Syslog", LogDetector.isLinuxSyslog],
       ["Linux Systemd", LogDetector.isLinuxSystemd],
       ["Linux Kernel", LogDetector.isLinuxKernel],
       ["Linux Audit", LogDetector.isLinuxAudit],
       ["Linux Package", LogDetector.isLinuxPackage],
        ["Windows Text", LogDetector.isWindowsText],
        ["Windows Application", LogDetector.isWindowsApplication],
        ["Windows Application TXT", LogDetector.isWindowsApplicationTXT],
        ["Windows Application CSV", LogDetector.isWindowsApplicationCSV],
        ["Windows System", LogDetector.isWindowsSystem],
        ["Windows Security", LogDetector.isWindowsSecurity],
        ["Windows Setup", LogDetector.isWindowsSetup],
        ["Windows Forwarded Events", LogDetector.isWindowsForwarded],
        ["Windows Event Viewer", LogDetector.isWindowsEventViewer],
        ["Windows Application", LogDetector.isWindowsApplicationTXT],
        ["JSON FTP Logs", LogDetector.isJsonFTPLogs],
      ["FileZilla FTP", LogDetector.isFilezilla],
      ["IIS FTP", LogDetector.isIisFtp],
      ["xferlog", LogDetector.isXferlog],
      ["Cloudflare", LogDetector.isCloudflare],
      ["AWS CloudTrail", LogDetector.isAwsCloudtrail],
      ["AWS GuardDuty", LogDetector.isAwsGuardduty],
      ["Azure Activity", LogDetector.isAzureActivity],
      ["GCP Audit", LogDetector.isGcpAudit],
      ["Kubernetes", LogDetector.isKubernetes],
      ["Docker", LogDetector.isDocker],
      ["Elasticsearch", LogDetector.isElasticsearch],
      ["Redis", LogDetector.isRedis],
      ["RabbitMQ", LogDetector.isRabbitmq],
      ["Kafka", LogDetector.isKafka],
      ["Zookeeper", LogDetector.isZookeeper],
      ["Nginx Error", LogDetector.isNginxError],
      ["Squid", LogDetector.isSquid],
      ["Suricata", LogDetector.isSuricata],
      ["Zeek", LogDetector.isZeek],
      ["Ossec", LogDetector.isOssec],
      ["Fail2ban", LogDetector.isFail2ban],
      ["Auth0", LogDetector.isAuth0],
      ["Apache Combined", LogDetector.isApacheCombined],
      ["DHCP", LogDetector.isDhcp],
      ["DNS", LogDetector.isDns],
      ["Proxy", LogDetector.isProxy],
      ["aiohttp", LogDetector.isAiohttp],
      ["Starlette", LogDetector.isStarlette],
    ];
  }

  private static checkLine(line: string, logType: string): boolean {
    const checkFunctions: Record<string, (line: string) => boolean> = {
      "Apache": LogDetector.isApache,
      "Apache Error": LogDetector.isApacheError,
      "Django": LogDetector.isDjango,
      "Flask": LogDetector.isFlask,
      "Node.js": LogDetector.isNode,
      "Express.js": LogDetector.isExpressJson,
      "FastAPI": LogDetector.isFastapiJson,
      "Laravel": LogDetector.isLaravel,
      "Ruby on Rails": LogDetector.isRails,
      "Gunicorn": LogDetector.isGunicorn,
      "Uvicorn": LogDetector.isUvicorn,
      "PHP-FPM": LogDetector.isPhpFpm,
      "NGINX": LogDetector.isNginx,
      "Caddy": LogDetector.isCaddy,
      "HAProxy": LogDetector.isHaproxy,
      "Spring Boot": LogDetector.isSpringBoot,
      "ASP.NET Core": LogDetector.isAspnetCore,
      "IIS": LogDetector.isIis,
      "Postfix": LogDetector.isPostfix,
      "Sendmail": LogDetector.isSendmail,
      "Exim": LogDetector.isExim,
      "Dovecot": LogDetector.isDovecot,
      "Courier": LogDetector.isCourier,
      "Microsoft Exchange": LogDetector.isExchange,
      "SMTP Server": LogDetector.isSmtpGeneric,
      "Amavis": LogDetector.isAmavis,
      "SpamAssassin": LogDetector.isSpamassassin,
      "MailScanner": LogDetector.isMailscanner,
      "Windows Firewall": LogDetector.isWindowsFw,
      "iptables": LogDetector.isIptables,
      "UFW": LogDetector.isUfw,
      "nftables": LogDetector.isNftables,
      "firewalld": LogDetector.isFirewalld,
      "macOS PF": LogDetector.isMacosPf,
      "macOS App Firewall": LogDetector.isMacosAppFw,
      "Palo Alto Firewall": LogDetector.isPaloAlto,
      "FortiGate": LogDetector.isFortigate,
      "Cisco ASA": LogDetector.isCiscoAsa,
      "Check Point Firewall": LogDetector.isCheckpoint,
      "AWS VPC Flow Logs": LogDetector.isAwsVpc,
      "Azure NSG Flow Logs": LogDetector.isAzureNsg,
      "GCP VPC Firewall": LogDetector.isGcpVpc,
      "Disk Traffic": LogDetector.isDiskTraffic,
       "Application Logs JSON": LogDetector.isApplicationJson,
       "Moodle LMS": LogDetector.isMoodleLms,
       "MySQL Error": LogDetector.isMysqlError,
      "MySQL Query": LogDetector.isMysqlQuery,
      "MySQL Slow Query": LogDetector.isMysqlSlow,
      "PostgreSQL Error": LogDetector.isPostgresError,
      "PostgreSQL Auth": LogDetector.isPostgresAuth,
      "PostgreSQL Statement": LogDetector.isPostgresStatement,
      "Oracle Alert": LogDetector.isOracleAlert,
      "Oracle Listener": LogDetector.isOracleListener,
      "Oracle Audit": LogDetector.isOracleAudit,
      "SQL Server Error": LogDetector.isSqlserverError,
      "SQL Server Audit": LogDetector.isSqlserverAudit,
      "SQL Server Transaction": LogDetector.isSqlserverTransaction,
      "MongoDB Server": LogDetector.isMongodbServer,
      "MongoDB Audit": LogDetector.isMongodbAudit,
      "Linux SSHD Failed": LogDetector.isLinuxSshdFailed,
      "Linux SSHD Accepted": LogDetector.isLinuxSshdAccepted,
      "Linux Syslog": LogDetector.isLinuxSyslog,
      "Linux Systemd": LogDetector.isLinuxSystemd,
      "Linux Kernel": LogDetector.isLinuxKernel,
      "Linux Audit": LogDetector.isLinuxAudit,
       "Linux Package": LogDetector.isLinuxPackage,
       "Windows Text": LogDetector.isWindowsText,
       "Windows Application": LogDetector.isWindowsApplication,
        "Windows Application TXT": LogDetector.isWindowsApplicationTXT,
        "Windows Application CSV": LogDetector.isWindowsApplicationCSV,
        "Windows System": LogDetector.isWindowsSystem,
       "Windows Security": LogDetector.isWindowsSecurity,
       "Windows Setup": LogDetector.isWindowsSetup,
       "Windows Forwarded Events": LogDetector.isWindowsForwarded,
       "Windows Event Viewer": LogDetector.isWindowsEventViewer,
       "JSON FTP Logs": LogDetector.isJsonFTPLogs,
      "FileZilla FTP": LogDetector.isFilezilla,
      "IIS FTP": LogDetector.isIisFtp,
      "xferlog": LogDetector.isXferlog,
      "Cloudflare": LogDetector.isCloudflare,
      "AWS CloudTrail": LogDetector.isAwsCloudtrail,
      "AWS GuardDuty": LogDetector.isAwsGuardduty,
      "Azure Activity": LogDetector.isAzureActivity,
      "GCP Audit": LogDetector.isGcpAudit,
      "Kubernetes": LogDetector.isKubernetes,
      "Docker": LogDetector.isDocker,
      "Elasticsearch": LogDetector.isElasticsearch,
      "Redis": LogDetector.isRedis,
      "RabbitMQ": LogDetector.isRabbitmq,
      "Kafka": LogDetector.isKafka,
      "Zookeeper": LogDetector.isZookeeper,
      "Nginx Error": LogDetector.isNginxError,
      "Squid": LogDetector.isSquid,
      "Suricata": LogDetector.isSuricata,
      "Zeek": LogDetector.isZeek,
      "Ossec": LogDetector.isOssec,
      "Fail2ban": LogDetector.isFail2ban,
      "Auth0": LogDetector.isAuth0,
      "Apache Combined": LogDetector.isApacheCombined,
      "DHCP": LogDetector.isDhcp,
      "DNS": LogDetector.isDns,
      "Proxy": LogDetector.isProxy,
      "aiohttp": LogDetector.isAiohttp,
      "Starlette": LogDetector.isStarlette,
    };
    
    return checkFunctions[logType]?.(line) ?? false;
  }

  private static readSampleLines(content: string): string[] {
    const trimmed = content.trim();
    
    // Handle JSON arrays (including JSON FTP logs) - return full content as single "line"
    if (trimmed.startsWith('[') && trimmed.length > 1000) {
      return [trimmed];
    }
    
    // For very large single-line JSON arrays, extract just the first few entries
    if (trimmed.startsWith('[[') && trimmed.length > 10000) {
      // Extract first 5000 chars and close the partial JSON
      const sample = trimmed.slice(0, 5000);
      // Try to find a complete entry pattern
      const bracketCount = (sample.match(/\[/g) || []).length;
      if (bracketCount > 10) {
        // Find a reasonable sample point - after first few complete entries
        return [sample];
      }
    }
    const lines = content.split('\n').map(l => l.trim());
    return lines.slice(0, LogDetector.SAMPLE_LINES);
  }

  static detect(content: string): string {
    // First, check for JSON FTP logs using full content
    if (LogDetector.isJsonFTPLogs(content)) {
      return 'JSON FTP Logs';
    }
    
    // Remove BOM character if present for proper detection
    let cleanContent = content;
    if (cleanContent.startsWith('\uFEFF') || cleanContent.startsWith('﻿')) {
      cleanContent = content.slice(1);
    }
    
    // Check for Windows Application/Event Viewer TXT formats (Level\t or Keywords\t)
    const trimmed = cleanContent.trim();
    
    // Check for Windows Application TXT header (Level\t) or CSV header (Level,)
    if (trimmed.startsWith('Level\t') || trimmed.startsWith('Level,')) {
      return 'Windows Application TXT';
    }
    
    // Check for Windows Event Viewer format (tab-separated or CSV)
    // Check for Windows Event Viewer header pattern
    if (trimmed.startsWith('Keywords\t') || trimmed.startsWith('Keywords,')) {
      // Check if content contains Windows Event Viewer data lines
      const lines = trimmed.split('\n');
      for (const line of lines) {
        if (line.includes('Audit ') && (line.includes('\t') || line.includes(',') || line.includes('-Windows-'))) {
          return 'Windows Event Viewer';
        }
      }
    }
    
    // Check for data line directly (no header) - tab format
    if (trimmed.includes('\t') && /^(Audit (?:Success|Failure|Error|Warning)|Success|Failure|Error|Warning)\t\d{2}-\d{2}-\d{4}/.test(trimmed)) {
      return 'Windows Event Viewer';
    }
    
    // Check for CSV data lines (comma-separated) using precompiled patterns
    if (LogDetector.WINDOWS_APPLICATION_CSV_RE.test(trimmed) ||
        LogDetector.WINDOWS_EVENTVIEWER_CSV_RE.test(trimmed)) {
      return 'Windows Application TXT';
    }
    
    // Also check for Level-based format (Information\t, Warning\t, Error\t)
    if (/^(Information|Warning|Error|Critical)\t\d{2}-\d{2}-\d{4}/.test(trimmed)) {
      return 'Windows Application TXT';
    }
    
    const lines = this.readSampleLines(cleanContent);

    if (lines.length === 0 || !lines[0]) {
      return 'Custom / Raw';
    }

    const priorityOrder = this.getPriorityOrder();
    const scores: Record<string, number> = {};
    for (const [logType] of priorityOrder) {
      scores[logType] = 0;
    }
    scores['Custom / Raw'] = 0;

    const phase1Lines = Math.min(LogDetector.CANDIDATE_SAMPLE_LINES, lines.length);
    const phase2Start = phase1Lines;

    for (let i = 0; i < phase1Lines; i++) {
      const line = lines[i];
      if (!line || line.startsWith('#')) continue;

      for (const [logType, checkFunc] of priorityOrder) {
        if (checkFunc(line)) {
          scores[logType] += 3;
        }
      }
    }

    if (phase2Start >= lines.length) {
      let bestType = 'Custom / Raw';
      let bestScore = 0;
      for (const [logType, score] of Object.entries(scores)) {
        if (score > bestScore) {
          bestScore = score;
          bestType = logType;
        }
      }
      return bestScore >= 3 ? bestType : 'Custom / Raw';
    }

    const candidateTypes = Object.entries(scores)
      .filter(([type, score]) => score > 0 && type !== 'Custom / Raw')
      .map(([type]) => type);

    if (candidateTypes.length === 0) {
      return 'Custom / Raw';
    }

    for (let i = phase2Start; i < lines.length; i++) {
      const line = lines[i];
      if (!line || line.startsWith('#')) continue;

      let matched = false;
      for (const logType of candidateTypes) {
        if (this.checkLine(line, logType)) {
          scores[logType] += 3;
          matched = true;
          break;
        }
      }

      if (!matched) {
        scores['Custom / Raw'] += 1;
      }
    }

    let bestType = 'Custom / Raw';
    let bestScore = 0;
    for (const [logType, score] of Object.entries(scores)) {
      if (score > bestScore) {
        bestScore = score;
        bestType = logType;
      }
    }

    return bestScore >= 3 ? bestType : 'Custom / Raw';
  }
}
