# Technique ID -> (name, tactic)
TECHNIQUES = {
    "T1566.001": ("Phishing: Spearphishing Attachment", "Initial Access"),
    "T1204.002": ("User Execution: Malicious File", "Execution"),
    "T1059.005": ("Command and Scripting Interpreter: Visual Basic", "Execution"),
    "T1055": ("Process Injection", "Defense Evasion"),
    "T1027": ("Obfuscated Files or Information", "Defense Evasion"),
    "T1003": ("OS Credential Dumping", "Credential Access"),
    "T1021.002": ("Remote Services: SMB/Windows Admin Shares", "Lateral Movement"),
    "T1071.001": ("Application Layer Protocol: Web Protocols", "Command and Control"),
}

# Malware family -> techniques (a starting point, see the note below)
FAMILIES = {
    "emotet":      ["T1566.001", "T1204.002", "T1059.005", "T1027", "T1071.001"],
    "qakbot":      ["T1566.001", "T1204.002", "T1055", "T1027", "T1071.001"],
    "dridex":      ["T1566.001", "T1204.002", "T1055", "T1071.001"],
    "trickbot":    ["T1566.001", "T1055", "T1003", "T1021.002", "T1071.001"],
    "bazarloader": ["T1566.001", "T1204.002", "T1055", "T1071.001"],
}

# Other names the feeds use for the same malware
ALIASES = {"heodo": "emotet", "quakbot": "qakbot", "qbot": "qakbot",
           "bazarbackdoor": "bazarloader"}

def normalize(name):
    n = (name or "").strip().lower()
    return ALIASES.get(n, n)
