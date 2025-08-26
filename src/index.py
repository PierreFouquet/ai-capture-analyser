# src/index.py

import sys
import os
import json
import asyncio
import logging
import time
import functools
import datetime
from typing import Literal, Optional, List, Dict, Any

# NOTE: The following imports are placeholders. You would need to ensure these libraries
# are available in the Cloudflare Workers environment or use their built-in equivalents.
# In a real-world scenario, you might use 'urllib3' or 'httpcore' which are often available.
# This code assumes a simple 'fetch' function is provided by the runtime.

# --- Cloudflare Worker Imports ---
from _worker import Request, Response

# --- Global Configuration and Utilities ---

# Load environment variables. Not needed in a worker env as bindings handle secrets.
# from dotenv import load_dotenv
# load_dotenv()

# --- Logging ---
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- LLM Utilities (from llm_utils.py) ---
LLM_CLIENTS = {}
AVAILABLE_LLM_MODELS = {}

def initialize_llm_clients(config: Dict[str, Any]):
    """Initializes LLM clients based on the provided configuration."""
    logger.info("Initializing LLM clients...")
    global LLM_CLIENTS
    global AVAILABLE_LLM_MODELS

    LLM_CLIENTS = {}
    AVAILABLE_LLM_MODELS = {}

    models_config = config.get('llm_models', {})
    for key, model_info in models_config.items():
        provider = model_info.get('provider')
        if provider == "Google":
            # In the worker environment, we use the `AI` binding
            # This is a placeholder, as the actual API call will be handled by the runtime's fetch.
            AVAILABLE_LLM_MODELS[key] = model_info
        elif provider == "OpenAI":
            AVAILABLE_LLM_MODELS[key] = model_info
        elif provider == "Anthropic":
            AVAILABLE_LLM_MODELS[key] = model_info
        elif provider == "Deepseek":
            AVAILABLE_LLM_MODELS[key] = model_info
        else:
            logger.warning(f"Unknown LLM provider: {provider} for model: {key}")

    logger.info(f"Available LLM models: {list(AVAILABLE_LLM_MODELS.keys())}")


async def call_llm(model_key: str, context: str, pcap_data_snippet: str, config: Dict[str, Any]) -> str:
    """Calls the appropriate LLM API based on the model key and returns the response."""
    model_info = AVAILABLE_LLM_MODELS.get(model_key)
    if not model_info:
        raise ValueError(f"Model key '{model_key}' not found in available models.")

    model_name = model_info.get('name')
    provider = model_info.get('provider')
    prompt_key = config['llm_settings'].get(f'prompt_key_{context}', f'{context}_pcap_explanation')
    prompt_template = config['llm_prompts'].get(prompt_key)
    schema = config['llm_prompts'].get(f'{prompt_key}_schema')

    if not prompt_template:
        raise ValueError(f"Prompt template for '{context}' not found.")
    if not schema:
        raise ValueError(f"Schema for '{context}' not found.")

    # Apply configuration variables to the prompt
    prompt = prompt_template.format(
        pcap_data_snippet=pcap_data_snippet,
        sip_udp_ports=config['voip_ports']['sip_udp'],
        sip_tcp_ports=config['voip_ports']['sip_tcp'],
        sip_tls_ports=config['voip_ports']['sip_tls'],
        rtp_udp_ports=config['voip_ports']['rtp_udp']
    )

    # In a real worker, this would use the `AI` binding
    # This is a placeholder for the actual API call
    logger.info(f"Calling LLM provider: {provider} with model: {model_name}")

    if provider == "Google":
        # Placeholder for Google API call
        # The worker's `AI` binding would be used here.
        # This function needs to be an async one to work with the worker.
        try:
            # We'll just return a mock response for now to demonstrate the flow
            # In a real app, this would be `env.AI.run(...)`
            return json.dumps({
                "summary": "This is a mock summary from a Google model.",
                "anomalies_and_errors": ["Mock anomaly 1", "Mock error 2"],
                "sip_rtp_info": "Mock SIP/RTP info.",
                "important_timestamps_packets": "Mock important packets."
            })
        except Exception as e:
            logger.error(f"Google LLM call failed: {e}")
            raise

    raise NotImplementedError(f"LLM provider '{provider}' is not implemented.")


# --- Report Renderer (from report_renderer.py) ---
ANALYSIS_TEMPLATE = """
<div class="report-section">
    <h2>Analysis Report: {{ filename }}</h2>
    <div class="summary-card">
        <h3>Summary</h3>
        <p>{{ report.summary }}</p>
    </div>
    <div class="details-card">
        <h3>Anomalies and Errors</h3>
        {% if report.anomalies_and_errors %}
            <ul>{% for item in report.anomalies_and_errors %}<li>{{ item }}</li>{% endfor %}</ul>
        {% else %}<p>N/A</p>{% endif %}
    </div>
    <div class="details-card">
        <h3>SIP/RTP Information</h3>
        <p>{{ report.sip_rtp_info }}</p>
    </div>
    <div class="details-card">
        <h3>Important Timestamps/Packets</h3>
        <p>{{ report.important_timestamps_packets }}</p>
    </div>
</div>
"""

def render_report(report: Dict, report_type: str, **kwargs) -> str:
    """Renders a single report based on its type and data."""
    # Jinja2 is not available in the worker environment.
    # We will use simple string formatting as a substitute.
    
    if report_type == "analysis":
        html = ANALYSIS_TEMPLATE.replace("{{ filename }}", kwargs.get("file_name", "File"))
        html = html.replace("{{ report.summary }}", report.get("summary", "N/A"))
        
        anomalies_list = "".join([f"<li>{item}</li>" for item in report.get("anomalies_and_errors", [])])
        if not anomalies_list:
            anomalies_list = "<p>N/A</p>"
        else:
            anomalies_list = f"<ul>{anomalies_list}</ul>"

        html = html.replace("<ul>{% for item in report.anomalies_and_errors %}<li>{{ item }}</li>{% endfor %}</ul>", anomalies_list)
        html = html.replace("{{ report.sip_rtp_info }}", report.get("sip_rtp_info", "N/A"))
        html = html.replace("{{ report.important_timestamps_packets }}", report.get("important_timestamps_packets", "N/A"))
        return html
    
    # We'll only implement the analysis renderer for this fix.
    return "Unsupported report type."

# --- Main Worker Logic (from index.py) ---

class AnalysisObject:
    def __init__(self, state, env):
        self.state = state
        self.env = env
        self.status = "idle"
        self.result = {}

        # The llm_utils functions are now part of this file
        self.llm_utils = sys.modules[__name__]
        
        # We need to load the status from storage in an async manner
        # but the constructor is sync. We'll handle this with a promise.
        self.state.storage.get("status").then(lambda s: setattr(self, 'status', s if s else self.status))

    async def fetch(self, request: Request) -> Response:
        try:
            url_path = request.url.path
            
            # Route based on the URL path
            if url_path.endswith("/status"):
                return self.handle_status_request()
            elif url_path.endswith("/process"):
                return await self.handle_process_request(request)
            else:
                return Response("Not Found", status=404)
        except Exception as e:
            return Response(f"An error occurred: {str(e)}", status=500)

    def handle_status_request(self) -> Response:
        # A simple status endpoint
        return Response(json.dumps({"status": self.status, "result": self.result}),
                        headers={"Content-Type": "application/json"})

    async def handle_process_request(self, request: Request) -> Response:
        if self.status != "idle":
            return Response("Already processing a request.", status=409)

        self.status = "processing"
        await self.state.storage.put("status", self.status)
        
        try:
            data = await request.json()
            pcap_data = data.get("pcap_data")
            file_name = data.get("file_name")
            llm_model_key = data.get("llm_model_key")

            if not pcap_data or not file_name or not llm_model_key:
                raise ValueError("Missing required parameters: pcap_data, file_name, or llm_model_key.")

            # Placeholder for PCAP processing
            # You would need to implement the actual logic for using pyshark on the worker
            # and extracting snippets.
            pcap_data_snippets = ["Placeholder packet data for demonstration"]
            
            # Now we call the function directly from the current module
            llm_response = await self.llm_utils.call_llm(
                llm_model_key,
                "analysis",
                pcap_data_snippet='\n'.join(pcap_data_snippets),
                config=self.env.config
            )

            report_data = json.loads(llm_response)

            html_report = render_report(report_data, "analysis", file_name=file_name)

            self.status = "complete"
            self.result = {"report": html_report}

        except Exception as e:
            self.status = "error"
            self.result = {"error": str(e)}
            return Response(f"Processing failed: {str(e)}", status=500)
        finally:
            await self.state.storage.put("status", self.status)
            await self.state.storage.put("result", self.result)
        
        return Response(json.dumps(self.result), headers={"Content-Type": "application/json"})

async def on_startup(env):
    initialize_llm_clients(env.config)

class Router:
    def __init__(self, env):
        self.env = env

    async def route(self, request: Request) -> Response:
        try:
            url = request.url
            if url.path == "/":
                return self.env.ASSETS.fetch(request)

            if url.path.startswith("/api/analyze"):
                session_id = request.headers.get("X-Session-ID") or "default"
                stub = self.env.ANALYSIS_OBJECT.get(self.env.ANALYSIS_OBJECT.id_from_name(session_id))
                return stub.fetch(request)

            return Response("Not Found", status=404)
        except Exception as e:
            return Response(f"An error occurred: {str(e)}", status=500)

async def on_fetch(request: Request, env):
    router = Router(env)
    return await router.route(request)
