import os
import subprocess
import time
import re
from datetime import datetime
from groq import Groq
from dotenv import load_dotenv

# --- Initialize OpenAI GPT-4o Mini LLM ---
load_dotenv()
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
groq_client = Groq(api_key=GROQ_API_KEY)

def query_llm(prompt):
    response = groq_client.chat.completions.create(
        model="llama-3.1-8b-instant",
        messages=[{"role": "system", "content": "You are an agentic cybersecurity assistant."},
                  {"role": "user", "content": prompt}],
        temperature=0.3,
    )
    response_dict = response.model_dump() 
    return response_dict["choices"][0]["message"]["content"]

# --- Scope Enforcement ---
def is_within_scope(target, allowed_domains):
    if target in allowed_domains:
        return True
    for domain in allowed_domains:
        if domain.startswith('.') and target.endswith(domain):
            return True
    return False

# --- Logging ---
LOG_FILE = "FinalReport.md"
def log_action(action, status, details):
    timestamp = datetime.now().isoformat()
    log_entry = f"[{timestamp}] {action} - {status}: {details}\n"
    print(log_entry)
    with open(LOG_FILE, "a") as f:
        f.write(log_entry)

# --- New Scan Logging Function ---
def log_scan_result(tool_name, result):
    """Log raw scan results to scanLog.txt"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open("scanLog.txt", "a") as f:
        f.write(f"=== {tool_name} Scan @ {timestamp} ===\n")
        f.write(f"{result}\n\n")

# --- Helper function to run shell commands ---
def run_command(command):
    try:
        result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
        return result.decode("utf-8")
    except subprocess.CalledProcessError as e:
        return f"Error: {e.output.decode('utf-8')}"

# --- Failure Detection and Recovery Mechanism ---

MAX_RETRIES = 2  # Configurable retry limit

def run_command(command):
    """Execute a shell command with failure detection."""
    try:
        result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, timeout=30)
        return result.decode("utf-8")
    except subprocess.TimeoutExpired:
        return "Error: Command timed out"
    except subprocess.CalledProcessError as e:
        return f"Error: {e.output.decode('utf-8')}"
    except Exception as e:
        return f"Error: Unexpected error - {str(e)}"

def detect_failure(output):
    """Detect failure based on common error patterns in tool output."""
    failure_patterns = ["Error:", "timed out", "failed", "command not found", "not found"]
    return any(pattern in output.lower() for pattern in failure_patterns)

def retry_with_alternate_params(command, alt_command, state, key):
    """Retry a failed task with alternate parameters."""
    retries = 0
    while retries < MAX_RETRIES:
        output = run_command(command)
        if not detect_failure(output):
            state[key] = output
            return state  # Success, return updated state

        log_action(key, "Retry", f"Attempt {retries+1} with alternate parameters")
        output = run_command(alt_command)  # Try alternate command
        if not detect_failure(output):
            state[key] = output
            return state  # Success, return updated state

        retries += 1
        time.sleep(2 ** retries)  # Exponential backoff

    log_action(key, "Failed", f"After {MAX_RETRIES} retries, skipping task.")
    state[key] = "Skipped due to repeated failures"
    return state

# --- Updated Node Functions with Failure Handling ---

def nmap_scan(state):
    target = state["target"]
    log_action("Nmap Scan", "Start", f"Scanning target: {target}")

    command = f"nmap -sS {target}"
    alt_command = f"nmap -Pn {target}"  # Alternative: Disable host discovery

    state = retry_with_alternate_params(command, alt_command, state, "nmap_result")
    state["ports_found"] = extract_open_ports(state["nmap_result"])
    log_scan_result("Nmap", state["nmap_result"])
    log_action("Nmap Scan", "Completed", f"Open ports: {state['ports_found']}")
    return state

def extract_open_ports(nmap_output):
    # Using regex to extract open ports from nmap output
    open_ports = re.findall(r"(\d+)/tcp\s+open", nmap_output)
    return open_ports

def gobuster_scan(state):
    target = state["target"]
    if any(p in state.get("ports_found", []) for p in ["80", "443"]):
        log_action("Gobuster Scan", "Start", f"Scanning directories on {target}")

        command = f"gobuster dir -w /usr/share/seclists/Discovery/Web-Content/common.txt -u https://{target} -b '' -fs 200 -t 100"
        alt_command = f"gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -u https://{target} -b ''"

        state = retry_with_alternate_params(command, alt_command, state, "gobuster_result")
        log_scan_result("Gobuster", state["gobuster_result"])
    else:
        state["gobuster_result"] = "Skipped (no web ports found)"
        log_scan_result("Gobuster", state["gobuster_result"])
        log_action("Gobuster Scan", "Skipped", "No web ports available")

    return state

def ffuf_scan(state):
    target = state["target"]
    if any(p in state.get("ports_found", []) for p in ["80", "443"]):
        log_action("FFUF Scan", "Start", f"Fuzzing {target} for hidden endpoints")

        command = f"ffuf -u https://{target}/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -fc 301,302 -mc 200"
        alt_command = f"ffuf -u https://{target}/FUZZ -w /usr/share/wordlists/dirb/common.txt -fc 301,302"

        state = retry_with_alternate_params(command, alt_command, state, "ffuf_result")
        log_scan_result("FFUF", state["ffuf_result"])
    else:
        state["ffuf_result"] = "Skipped (no web ports found)"
        log_scan_result("FFUF", state["ffuf_result"])
        log_action("FFUF Scan", "Skipped", "No web ports available")

    return state


def supervisor(state):
    log_action("Supervisor", "Start", "Analyzing scan outputs with LLM")
    nmap_output = state.get("nmap_result", "No result")
    gobuster_output = state.get("gobuster_result", "No result")
    ffuf_output = state.get("ffuf_result", "No result")
    
    prompt = f"""
    Analyze the following scan results and identify any potential security vulnerabilities:
    
    🔍 Nmap Scan:
    {nmap_output}
    
    📂 Gobuster Scan:
    {gobuster_output}
    
    🔎 FFUF Scan:
    {ffuf_output}
    
    Provide a point-wise summary report highlighting (with the actual corresponding output to support the report, make sure the report is not verbose and only highlights the important vulnerabilities):
    - Any identified vulnerabilities
    - Suspicious ports, directories, or endpoints
    - Recommendations for further investigation
    **Make it as consice and to the point as possible.**
    """
    report = query_llm(prompt)
    
    with open(LOG_FILE, "w") as f:
        f.write(report)
    
    log_action("Supervisor", "Completed", "Final Report Generated")
    state["final_report"] = report
    return state

class SecurityScanGraph:
    def __init__(self):
        self.nodes = {}
        self.edges = {}
        self.entry_point = None

    def add_node(self, name, func):
        self.nodes[name] = func

    def add_edge(self, from_node, to_node):
        self.edges.setdefault(from_node, []).append(to_node)

    def set_entry_point(self, name):
        self.entry_point = name

    def compile(self):
        def executor(initial_state):
            current_state = initial_state
            current_node = self.entry_point
            while current_node is not None:
                func = self.nodes[current_node]
                current_state = func(current_state)
                next_nodes = self.edges.get(current_node, [])
                current_node = next_nodes[0] if next_nodes else None
            return current_state
        return executor

def main():
    ALLOWED_DOMAINS = ["google.com", ".example.com"]
    target = "google.com"
    if not is_within_scope(target, ALLOWED_DOMAINS):
        log_action("Scope Enforcement", "Blocked", f"Target {target} is outside allowed scope.")
        raise Exception("Target out of scope.")
    
    initial_state = {"target": target}
    graph = SecurityScanGraph()
    graph.add_node("nmap_scan", nmap_scan)
    graph.add_node("gobuster_scan", gobuster_scan)
    graph.add_node("ffuf_scan", ffuf_scan)
    graph.add_node("supervisor", supervisor)
    graph.add_edge("nmap_scan", "gobuster_scan")
    graph.add_edge("gobuster_scan", "ffuf_scan")
    graph.add_edge("ffuf_scan", "supervisor")
    graph.set_entry_point("nmap_scan")
    executor = graph.compile()
    final_state = executor(initial_state)
    print("\nScan Complete. Final State:")
    print(final_state)

if __name__ == "__main__":
    main()