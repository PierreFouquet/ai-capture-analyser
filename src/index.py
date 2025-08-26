# src/index.py
#
# This script consolidates and refactors the packet capture analysis
# and comparison application to run natively on Cloudflare Workers.
# It leverages Durable Objects for stateful, long-running tasks and
# Cloudflare AI and R2 bindings for services.
#
# This version assumes PCAP parsing is handled on the client-side,
# and the Worker receives a text-based packet log.
#
# To run this, ensure your `wrangler.toml` is configured with the
# necessary bindings for `AI`, `ASSETS`, `CAPTURE_BUCKET`, and a
# Durable Object named `ANALYSIS_OBJECT`.

import uuid
import json
import yaml
import asyncio
from js import Response, Request

# A simple class to represent the HTTP response for JSON data
class JSONResponse(Response):
    def __init__(self, data, status=200):
        super().__init__(json.dumps(data), status=status, headers={"Content-Type": "application/json"})

# --- Helper Functions ---

# Helper function to get configuration from the ASSETS binding.
# The config.yaml file should be placed in a `public` directory
# in your project.
async def get_config(env):
    try:
        config_obj = await env.ASSETS.get("config.yaml")
        if not config_obj:
            return {"error": "Config file not found"}
        config_text = await config_obj.text()
        return yaml.safe_load(config_text)
    except Exception as e:
        return {"error": f"Failed to load config: {e}"}

# This function calls the Cloudflare AI binding. It replaces the
# original llm_utils.py script's logic.
async def call_llm(env, config, model_key, prompt):
    """
    Calls a specific LLM model using the Cloudflare AI binding.
    
    Args:
        env: The Cloudflare Worker environment object.
        config: The application configuration dictionary.
        model_key: The key from the config file (e.g., 'gemini-2.5-pro').
        prompt: The text prompt to send to the LLM.
    
    Returns:
        The text response from the LLM.
    """
    try:
        # Get the Cloudflare model name from the config
        model_name = config['llm_models'][model_key]['cloudflare_name']
        
        # Run the model via the AI binding
        response = await env.AI.run(
            model_name,
            messages=[{"role": "user", "content": prompt}]
        )
        
        if response and response.choices:
            return response.choices[0].message.content
        else:
            return {"error": "No valid response from LLM"}
    except Exception as e:
        return {"error": f"Error calling AI: {e}"}

# Placeholder for parsing the LLM's JSON output.
# This should be adapted from the original llm_utils.py
def parse_and_validate_llm_response(response_text, schema):
    try:
        data = json.loads(response_text)
        # TODO: Implement full schema validation here.
        # This is a simplified check.
        if isinstance(data, dict):
            return {"status": "success", "data": data}
        else:
            return {"status": "error", "message": "Invalid JSON format."}
    except json.JSONDecodeError as e:
        return {"status": "error", "message": f"JSON decoding failed: {e}"}

# --- Durable Object Class ---
# This class handles the state and long-running operations. Each
# instance is tied to a single analysis or comparison job.
class AnalysisObject:
    def __init__(self, state, env):
        self.state = state
        self.env = env
        self.config = None
        # Initialize state, restoring from storage if available.
        self.status = "idle"
        self.report_data = None
        self.state.storage.get("status").then(lambda s: self.status = s if s else self.status)
        self.state.storage.get("report").then(lambda r: self.report_data = r)

    async def fetch(self, request):
        """
        The fetch handler for the Durable Object. This function receives
        requests from the main Worker.
        """
        url_path = request.url.pathname.strip('/')
        
        # Load configuration upon first request
        if not self.config:
            self.config = await self.get_config()
            if "error" in self.config:
                return JSONResponse(self.config, status=500)
        
        if url_path == "start-analysis":
            # Start the analysis as a background task
            ctx.waitUntil(self.start_analysis(request))
            
            # Persist status to Durable Object storage
            await self.state.storage.put('status', 'processing')
            self.status = 'processing'
            return JSONResponse({"status": "Analysis started"})

        elif url_path == "start-comparison":
            # Start the comparison as a background task
            ctx.waitUntil(self.start_comparison(request))
            
            # Persist status
            await self.state.storage.put('status', 'processing')
            self.status = 'processing'
            return JSONResponse({"status": "Comparison started"})

        elif url_path == "get-status":
            # Return the current job status and report data
            return JSONResponse({
                "status": self.status,
                "report": self.report_data
            })
        
        return JSONResponse({"error": "Not Found"}, status=404)

    # Loads the config from R2, allowing it to be managed independently
    async def get_config(self):
        try:
            # We can now get the config from ASSETS, since it's a small file.
            config_obj = await self.env.ASSETS.get("config.yaml")
            if not config_obj:
                return {"error": "Config file not found in ASSETS"}
            config_text = await config_obj.text()
            return yaml.safe_load(config_text)
        except Exception as e:
            return {"error": f"Failed to load config from ASSETS: {e}"}

    async def start_analysis(self, request):
        """
        Handles the PCAP analysis logic. This version takes the
        pre-parsed packet data as a string from the request.
        """
        try:
            body = await request.json()
            pcap_data_snippet = body.get('pcap_data')
            
            if not pcap_data_snippet:
                raise ValueError("No PCAP data provided in request body.")
            
            # Use the provided text data directly in the prompt
            prompt = self.config['llm_prompts']['analysis_pcap_explanation'].format(
                pcap_data_snippet=pcap_data_snippet,
                sip_udp_ports=self.config['protocol_ports']['sip_udp_ports'],
                rtp_udp_ports=self.config['protocol_ports']['rtp_udp_ports']
            )
            
            llm_response = await call_llm(self.env, self.config, "gemini-2.5-flash", prompt)
            
            # Assuming llm_response is a JSON string
            report = parse_and_validate_llm_response(
                llm_response,
                self.config['llm_prompts']['analysis_pcap_explanation_schema']
            )
            
            if report['status'] == 'success':
                await self.state.storage.put("report", report['data'])
                await self.state.storage.put("status", "complete")
                self.report_data = report['data']
                self.status = "complete"
            else:
                await self.state.storage.put("status", "failed")
                await self.state.storage.put("error", report['message'])
                self.status = "failed"

        except Exception as e:
            await self.state.storage.put("status", "failed")
            await self.state.storage.put("error", str(e))
            self.status = "failed"
    
    async def start_comparison(self, request):
        """
        Handles the PCAP comparison logic. This version takes two
        pre-parsed packet data strings from the request.
        """
        try:
            body = await request.json()
            pcap_data_snippet1 = body.get('pcap_data1')
            pcap_data_snippet2 = body.get('pcap_data2')

            if not pcap_data_snippet1 or not pcap_data_snippet2:
                raise ValueError("Two PCAP data snippets are required.")

            # Create the prompt for comparison
            prompt = self.config['llm_prompts']['comparison_explanation'].format(
                pcap_data_snippet1=pcap_data_snippet1,
                pcap_data_snippet2=pcap_data_snippet2,
            )

            llm_response = await call_llm(self.env, self.config, "gemini-2.5-flash", prompt)
            
            report = parse_and_validate_llm_response(
                llm_response,
                self.config['llm_prompts']['comparison_explanation_schema']
            )

            if report['status'] == 'success':
                await self.state.storage.put("report", report['data'])
                await self.state.storage.put("status", "complete")
                self.report_data = report['data']
                self.status = "complete"
            else:
                await self.state.storage.put("status", "failed")
                await self.state.storage.put("error", report['message'])
                self.status = "failed"

        except Exception as e:
            await self.state.storage.put("status", "failed")
            await self.state.storage.put("error", str(e))
            self.status = "failed"


# --- Main Worker `fetch` Handler ---
# This is the entry point for all incoming requests. It serves as a
# router to the correct Durable Object instance.
async def fetch(request, env, ctx):
    url_path = request.url.pathname.strip('/')
    
    if url_path == "start-job":
        body = await request.json()
        job_type = body.get('job_type') # e.g., "analyze" or "compare"
        
        # Create a unique job ID
        job_id = str(uuid.uuid4())
        
        # Get the Durable Object stub using the job ID
        durable_object_id = env.ANALYSIS_OBJECT.idFromName(job_id)
        durable_object_stub = env.ANALYSIS_OBJECT.get(durable_object_id)
        
        # Forward the request to the Durable Object. The DO's `fetch`
        # handler will determine what to do based on the body/URL.
        response = await durable_object_stub.fetch(request)
        
        return JSONResponse({"jobId": job_id, "status": "Job started", "type": job_type})

    elif url_path.startswith("get-status"):
        job_id = url_path.split('/')[-1]
        
        if not job_id:
            return JSONResponse({"error": "Job ID is required"}, status=400)
            
        durable_object_id = env.ANALYSIS_OBJECT.idFromName(job_id)
        durable_object_stub = env.ANALYSIS_OBJECT.get(durable_object_id)
        
        # Forward the status request to the Durable Object
        status_response = await durable_object_stub.fetch("get-status")
        return status_response

    return JSONResponse({"error": "Not Found"}, status=404)

# Export the fetch handler and the Durable Object class
export { fetch, AnalysisObject };