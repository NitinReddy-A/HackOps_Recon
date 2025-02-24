import streamlit as st
import os
import subprocess
import time
import re
from datetime import datetime
from groq import Groq
from dotenv import load_dotenv
import psutil

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

# --- Custom CSS for Hacker Theme ---
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Source+Code+Pro:wght@300;400;600&display=swap');
    
    html, body, [class*="css"] {
        font-family: 'Source Code Pro', monospace;
        background-color: #0a0a0a;
        color: #00ff00;
    }
    
    .stButton>button {
        background: #1a1a1a;
        color: #00ff00;
        border: 1px solid #00ff00;
        border-radius: 3px;
        transition: all 0.3s;
    }
    
    .stButton>button:hover {
        background: #003300;
        color: #00ff00;
        border: 1px solid #00ff00;
    }
    
    .stTextInput>div>div>input {
        background: #1a1a1a;
    }
    
    .stTextArea>div>div>textarea {
        background: #1a1a1a;
    }
    
    .stProgress>div>div>div {
        background-color: #00ff00;
    }
    
    .terminal-box {
        border: 1px solid #00ff00;
        border-radius: 5px;
        padding: 1rem;
        margin: 1rem 0;
        background-color: #001a00;
        color: #00ff00;
        font-family: 'Source Code Pro', monospace;
    }
    
    .scan-header {
        color: #00ff00;
        border-bottom: 2px solid #00ff00;
        padding-bottom: 0.5rem;
        margin: 1rem 0;
    }
    
    .hacker-alert {
        color: #ff0000;
        background-color: #330000;
        padding: 1rem;
        border: 1px solid #ff0000;
        border-radius: 5px;
        margin: 1rem 0;
    }
</style>
""", unsafe_allow_html=True)

# --- ASCII Art Banner ---
ASCII_BANNER = r"""
██╗  ██╗ █████╗  ██████╗ ██╗  ██╗ ██████╗ ██████╗ ███████╗
██║  ██║██╔══██╗██╔════╝ ██║  ██║██╔═══██╗██╔══██╗██╔════╝
███████║███████║██║  ███╗███████║██║   ██║██████╔╝███████╗
██╔══██║██╔══██║██║   ██║██╔══██║██║   ██║██╔═══╝ ╚════██║
██║  ██║██║  ██║╚██████╔╝██║  ██║╚██████╔╝██║     ███████║
╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚══════╝
          ⚡ HackOps Recon: Scan. Exploit. Own. ⚡
                                                      
"""

# --- Main Function with Enhanced UI ---
# ... (keep previous imports and CSS)

def main():
    st.markdown(f"```css\n{ASCII_BANNER}\n```")
    st.markdown("### LLM-Powered Autonomous Cyber Scanner")

    # Initialize session state
    if 'scan_complete' not in st.session_state:
        st.session_state.scan_complete = False
    if 'final_report' not in st.session_state:
        st.session_state.final_report = ""
    if 'scan_log' not in st.session_state:
        st.session_state.scan_log = ""
    if 'scan_metrics' not in st.session_state:
        st.session_state.scan_metrics = {
            'start_time': time.time(),
            'duration': 0,
            'llm_time': 0,
            'throughput': 0
        }

    # Sidebar controls
    with st.sidebar:
        st.markdown("### ⚙️ Control Panel")
        target = st.text_input("TARGET", "google.com")
        allowed_domains = st.text_area("ALLOWED DOMAINS", "google.com\n.example.com\nirctc.co.in").split('\n')
        st.markdown("---")
        run_scan = st.button("🚀 INITIATE CYBER SCAN", use_container_width=True)
        st.markdown("---")
        st.markdown("### 🔍 SCAN STATUS")
        status_display = st.empty()

    # Main content area
    if run_scan:
        if not is_within_scope(target, allowed_domains):
            st.markdown(f"""
            <div class="hacker-alert">
                🚨 TARGET {target} OUTSIDE SCOPE! ENGAGING SAFETY PROTOCOLS...
            </div>
            """, unsafe_allow_html=True)
            return

        # Initialize scan graph
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

        # Execute scan with time tracking
        
        llm_processing_time = 0
        
        with st.expander("🔎 LIVE SCAN OPERATIONS", expanded=True):
            terminal_output = st.empty()
            nodes = ["nmap_scan", "gobuster_scan", "ffuf_scan", "supervisor"]
            
            for i, node in enumerate(nodes):
                # Update status display
                status_messages = [
                    ("🚀 INITIALIZING CYBER SCAN PROTOCOL...", "yellow"),
                    ("🔍 PORT SCANNING ENGAGED...", "cyan"),
                    ("📂 DIRECTORY ENUMERATION IN PROGRESS...", "green"),
                    ("🧠 AI ANALYSIS INITIATED...", "blue")
                ]
                status_text, color = status_messages[i]
                status_display.markdown(
                    f"<span style='color:{color};'>▌{status_text}</span>",
                    unsafe_allow_html=True
                )

                # Execute node with timing
                node_start = time.time()
                initial_state = graph.nodes[node](initial_state)
                node_time = time.time() - node_start

                # Track LLM processing time specifically
                if node == "supervisor":
                    llm_processing_time = node_time

                # Update terminal display
                term_content = f"""
                [~] Executed {node.replace('_', ' ').upper()}
                [⏱] Execution time: {node_time:.2f}s
                {"▔"*40}
                """
                terminal_output.code(term_content, language="bash")

        # Calculate metrics
        total_duration = time.time() - st.session_state.scan_metrics['start_time']
        try:
            log_size = os.path.getsize("scanLog.txt") / 1024  # KB
            data_throughput = log_size / total_duration if total_duration > 0 else 0
        except FileNotFoundError:
            data_throughput = 0

        # Store metrics in session state
        st.session_state.scan_metrics = {
            'duration': total_duration,
            'llm_time': llm_processing_time,
            'throughput': data_throughput
        }

        # Update session state
        st.session_state.scan_complete = True
        st.session_state.final_report = initial_state.get("final_report", "")
        with open("scanLog.txt", "r") as f:
            st.session_state.scan_log = f.read()

        status_display.markdown(
            "<span style='color:#00ff00;'>✅ CYBER SCAN PROTOCOL COMPLETED</span>",
            unsafe_allow_html=True
        )

    # Display results
    if st.session_state.scan_complete:
        # Download Section
        st.markdown("---")
        st.markdown("### 📥 DATA EXFILTRATION")
        col1, col2 = st.columns(2)
        with col1:
            st.download_button(
                label="💾 DOWNLOAD REPORT",
                data=st.session_state.final_report,
                file_name="CYBER_REPORT.md",
                mime="text/markdown",
                use_container_width=True
            )
        with col2:
            st.download_button(
                label="💾 DOWNLOAD MARKDOWN_LOGS",
                data=st.session_state.scan_log,
                file_name="SCAN_LOGS.txt",
                mime="text/plain",
                use_container_width=True
            )
        st.markdown("---")
        st.markdown("### 📡 SCAN RESULTS")
        
        tab1, tab2 = st.tabs(["AI ANALYSIS REPORT", "SCAN METRICS"])
        with tab1:
            st.markdown("### 🔍 Analysis Results")
            st.markdown(st.session_state.final_report)

        with tab2:
            st.markdown("#### 📊 SCAN METRICS")
            col1, col2, col3 = st.columns(3)
            col1.metric("TOTAL DURATION", f"{st.session_state.scan_metrics['duration']:.2f}s")
            col2.metric("AI PROCESSING", f"{st.session_state.scan_metrics['llm_time']:.2f}s")
            col3.metric("DATA THROUGHPUT", f"{st.session_state.scan_metrics['throughput']:.2f} KB/s")
            
        st.markdown("---")


if __name__ == "__main__":
    main()