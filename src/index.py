# src/index.py

import sys
import os
import json
import asyncio
from typing import Literal
import llm_utils
import report_renderer

# This is a placeholder for the aiohttp/httpx/etc. client
# It will be provided by the Workers AI environment at runtime
# In a real-world scenario, you would use a library like 'requests-async' or 'aiohttp'
# but for this example, we assume a simple 'fetch' function is available.
# We also assume that llm_utils.py is configured to use this fetch function.
fetch = None # This will be set by the runtime

# The following classes are defined for Python Workers and are automatically exported
# Durable Objects are stateful and persist data across requests.
class AnalysisObject:
    def __init__(self, state, env):
        self.state = state
        self.env = env
        self.status = "idle"
        self.result = {}
        self.llm_utils = llm_utils

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
            # Assuming the request body contains the PCAP data and other parameters
            data = await request.json()
            pcap_data = data.get("pcap_data")
            file_name = data.get("file_name")
            llm_model_key = data.get("llm_model_key")

            if not pcap_data or not file_name or not llm_model_key:
                raise ValueError("Missing required parameters: pcap_data, file_name, or llm_model_key.")

            # This part is a placeholder. You would need to implement the actual
            # PCAP processing logic, likely involving PyShark on the worker.
            # The PCAP file needs to be stored temporarily, processed, and then
            # the snippets sent to the LLM.
            
            pcap_data_snippets = ["Placeholder packet data for demonstration"]
            
            # Correctly calling the LLM utility function. Assuming it's adapted for async.
            llm_response = await self.llm_utils.call_llm(
                llm_model_key,
                "analysis",
                pcap_data_snippet='\n'.join(pcap_data_snippets),
                config=self.env.config
            )

            # Assuming the LLM response needs to be parsed
            report_data = json.loads(llm_response)

            # Use the report_renderer to create the HTML
            html_report = report_renderer.render_report(report_data, "analysis", file_name=file_name)

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
    # This function is called when the worker starts.
    # We can use it to initialize our LLM clients.
    llm_utils.initialize_llm_clients(env.config)

class Router:
    def __init__(self, env):
        self.env = env

    async def route(self, request: Request) -> Response:
        try:
            url = request.url
            if url.path == "/":
                # Serve the index.html from the static assets
                return self.env.ASSETS.fetch(request)

            if url.path.startswith("/api/analyze"):
                # Use a unique ID for each analysis session
                session_id = request.headers.get("X-Session-ID") or "default"
                stub = self.env.ANALYSIS_OBJECT.get(self.env.ANALYSIS_OBJECT.id_from_name(session_id))
                return stub.fetch(request)

            return Response("Not Found", status=404)
        except Exception as e:
            return Response(f"An error occurred: {str(e)}", status=500)

async def on_fetch(request: Request, env):
    router = Router(env)
    return await router.route(request)
