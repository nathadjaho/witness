import os

# --- Vultr Serverless Inference (OpenAI-compatible). Keys live ONLY here, in the
# control plane. They are never passed to a sandbox.
INFERENCE_BASE_URL = os.environ.get("VULTR_INFERENCE_BASE_URL", "https://api.vultrinference.com/v1")
INFERENCE_API_KEY = os.environ.get("VULTR_INFERENCE_API_KEY", "")
PLANNER_MODEL = os.environ.get("PLANNER_MODEL", "")      # pick from the live model list
VISION_MODEL = os.environ.get("VISION_MODEL", "")        # optional: screenshot verification
MOCK_LLM = os.environ.get("MOCK_LLM", "0") == "1" or not INFERENCE_API_KEY

# --- Sandbox
RUNNER_IMAGE = os.environ.get("RUNNER_IMAGE", "witness-runner:latest")
SANDBOX_RUNTIME = os.environ.get("SANDBOX_RUNTIME", "")   # "runsc" when gVisor is installed
SANDBOX_NETWORK = os.environ.get("SANDBOX_NETWORK", "witness_sandbox")
PROXY_URL_FOR_SANDBOX = os.environ.get("PROXY_URL_FOR_SANDBOX", "http://172.30.0.2:3128")
PROXY_ADMIN_URL = os.environ.get("PROXY_ADMIN_URL", "http://egress-proxy:9090")
PROXY_ADMIN_TOKEN = os.environ.get("PROXY_ADMIN_TOKEN", "")
SANDBOX_TIMEOUT_S = int(os.environ.get("SANDBOX_TIMEOUT_S", "35"))
SANDBOX_MEMORY = os.environ.get("SANDBOX_MEMORY", "1g")
SANDBOX_CPUS = os.environ.get("SANDBOX_CPUS", "1")
SANDBOX_PIDS = os.environ.get("SANDBOX_PIDS", "256")

# Where screenshots are written. HOST_ARTIFACTS_DIR is the same directory as
# seen by the Docker daemon (they differ when the orchestrator itself runs in
# a container with the docker socket mounted).
ARTIFACTS_DIR = os.environ.get("ARTIFACTS_DIR", "/data/artifacts")
HOST_ARTIFACTS_DIR = os.environ.get("HOST_ARTIFACTS_DIR", ARTIFACTS_DIR)
DB_PATH = os.environ.get("DB_PATH", "/data/witness.db")

# Hosts on the private network the sandbox may reach (the attack lab site).
TRAP_SITE = os.environ.get("TRAP_SITE", "http://trap-site:8080")

MAX_COMPANIES = int(os.environ.get("MAX_COMPANIES", "8"))
MAX_PAGES_PER_COMPANY = int(os.environ.get("MAX_PAGES_PER_COMPANY", "4"))
MAX_CONCURRENT_RUNS = int(os.environ.get("MAX_CONCURRENT_RUNS", "2"))
REASONING_EFFORT = os.environ.get("REASONING_EFFORT", "low")  # "" to leave the model default
