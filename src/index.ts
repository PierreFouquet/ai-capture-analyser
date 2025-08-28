// The Durable Object that will handle the analysis state.
export interface AnalysisObjectState {
    status: 'idle' | 'processing' | 'complete' | 'error';
    result: any;
}

export class AnalysisObject {
    private state: DurableObjectState;
    private env: Env;
    private status: 'idle' | 'processing' | 'complete' | 'error';
    private result: any;

    constructor(state: DurableObjectState, env: Env) {
        this.state = state;
        this.env = env;
        this.status = 'idle';
        this.result = {};

        // Load status from storage
        this.state.storage.get<AnalysisObjectState['status']>('status')
            .then(s => this.status = s || 'idle');
    }

    // Handle requests to the Durable Object
    async fetch(request: Request): Promise<Response> {
        try {
            const url = new URL(request.url);
            const path = url.pathname;

            if (path.endsWith("/status")) {
                return this.handleStatusRequest();
            } else if (path.endsWith("/process")) {
                return await this.handleProcessRequest(request);
            } else {
                return new Response("Not Found", { status: 404 });
            }
        } catch (e: any) {
            return new Response(`An error occurred: ${e.message}`, { status: 500 });
        }
    }

    private handleStatusRequest(): Response {
        return new Response(JSON.stringify({
            status: this.status,
            result: this.result,
        }), {
            headers: { 'Content-Type': 'application/json' },
        });
    }

    private async handleProcessRequest(request: Request): Promise<Response> {
        if (this.status !== 'idle') {
            return new Response("Already processing a request.", { status: 409 });
        }

        this.status = 'processing';
        await this.state.storage.put('status', this.status);

        try {
            const data = await request.json() as { pcap_data: string; file_name: string; llm_model_key: string };
            const { pcap_data, file_name, llm_model_key } = data;

            if (!pcap_data || !file_name || !llm_model_key) {
                throw new Error("Missing required parameters: pcap_data, file_name, or llm_model_key.");
            }

            // In a real implementation, you would parse the PCAP data here
            // For this example, we'll use placeholder data
            const pcapDataSnippets = ["Placeholder packet data for demonstration"];
            
            const llmResponse = await this.callLLM(
                llm_model_key,
                "analysis",
                pcapDataSnippets.join('\n'),
                this.env.config
            );

            const reportData = JSON.parse(llmResponse);
            const htmlReport = this.renderReport(reportData, "analysis", { file_name });

            this.status = 'complete';
            this.result = { report: htmlReport };

        } catch (e: any) {
            this.status = 'error';
            this.result = { error: e.message };
            return new Response(`Processing failed: ${e.message}`, { status: 500 });
        } finally {
            await this.state.storage.put('status', this.status);
            await this.state.storage.put('result', this.result);
        }

        return new Response(JSON.stringify(this.result), {
            headers: { 'Content-Type': 'application/json' },
        });
    }

    private async callLLM(model_key: string, context: string, pcap_data_snippet: string, config: any): Promise<string> {
        const modelInfo = config.llm_models[model_key];
        if (!modelInfo) {
            throw new Error(`Model key '${model_key}' not found.`);
        }

        const modelName = modelInfo.name;
        const provider = modelInfo.provider;
        const promptKey = config.llm_settings[`prompt_key_${context}`] || `${context}_pcap_explanation`;
        const promptTemplate = config.llm_prompts[promptKey];
        const schema = config.llm_prompts[`${promptKey}_schema`];

        if (!promptTemplate) {
            throw new Error(`Prompt template for '${context}' not found.`);
        }
        if (!schema) {
            throw new Error(`Schema for '${context}' not found.`);
        }

        const prompt = promptTemplate
            .replace('{pcap_data_snippet}', pcap_data_snippet)
            .replace('{sip_udp_ports}', config.voip_ports.sip_udp.join(', '))
            .replace('{sip_tcp_ports}', config.voip_ports.sip_tcp.join(', '))
            .replace('{sip_tls_ports}', config.voip_ports.sip_tls.join(', '))
            .replace('{rtp_udp_ports}', config.voip_ports.rtp_udp.join(', '));

        console.log(`Calling LLM provider: ${provider} with model: ${modelName}`);

        // Handle different providers
        if (provider === "Cloudflare") {
            // Use Cloudflare AI binding
            const ai = this.env.AI;
            const inputs = {
                prompt: prompt,
                max_tokens: config.llm_settings.max_tokens || 4096,
                temperature: config.llm_settings.temperature || 0.1
            };
            
            try {
                const response = await ai.run(model_key, inputs);
                // The response from Cloudflare AI might be a text string, so we need to parse it as JSON
                if (typeof response === 'string') {
                    try {
                        // Try to parse as JSON
                        return response;
                    } catch (e) {
                        // If it's not JSON, wrap it in a proper JSON structure
                        return JSON.stringify({
                            summary: response,
                            anomalies_and_errors: [],
                            sip_rtp_info: "N/A",
                            important_timestamps_packets: "N/A"
                        });
                    }
                } else {
                    return JSON.stringify(response);
                }
            } catch (e: any) {
                console.error("Error calling Cloudflare AI:", e);
                throw new Error(`Failed to call Cloudflare AI: ${e.message}`);
            }
        } else if (provider === "Google") {
            // Note: In the actual worker, you would use the AI binding like this:
            // const ai = this.env.AI;
            // const llm_response = await ai.run(modelName, { prompt, schema });
            // For this example, we return a mock response.
            return JSON.stringify({
                "summary": "This is a mock summary from a Google model.",
                "anomalies_and_errors": ["Mock anomaly 1", "Mock error 2"],
                "sip_rtp_info": "Mock SIP/RTP info.",
                "important_timestamps_packets": "Mock important packets."
            });
        } else if (provider === "OpenAI") {
            // Implement OpenAI call
            // Mock response for now
            return JSON.stringify({
                "summary": "This is a mock summary from an OpenAI model.",
                "anomalies_and_errors": ["OpenAI mock anomaly"],
                "sip_rtp_info": "OpenAI mock SIP/RTP info.",
                "important_timestamps_packets": "OpenAI mock important packets."
            });
        } else if (provider === "Anthropic") {
            // Implement Anthropic call
            // Mock response for now
            return JSON.stringify({
                "summary": "This is a mock summary from an Anthropic model.",
                "anomalies_and_errors": ["Anthropic mock anomaly"],
                "sip_rtp_info": "Anthropic mock SIP/RTP info.",
                "important_timestamps_packets": "Anthropic mock important packets."
            });
        } else if (provider === "Deepseek") {
            // Implement Deepseek call
            // Mock response for now
            return JSON.stringify({
                "summary": "This is a mock summary from a Deepseek model.",
                "anomalies_and_errors": ["Deepseek mock anomaly"],
                "sip_rtp_info": "Deepseek mock SIP/RTP info.",
                "important_timestamps_packets": "Deepseek mock important packets."
            });
        }

        throw new Error(`LLM provider '${provider}' is not implemented.`);
    }

    private renderReport(report: any, report_type: string, kwargs: { [key: string]: any }): string {
        if (report_type === "analysis") {
            let html = `
                <div class="report-section">
                    <h2>Analysis Report: ${kwargs.file_name || 'File'}</h2>
                    <div class="summary-card">
                        <h3>Summary</h3>
                        <p>${report.summary || 'N/A'}</p>
                    </div>
                    <div class="details-card">
                        <h3>Anomalies and Errors</h3>
                        ${report.anomalies_and_errors && report.anomalies_and_errors.length > 0 ?
                            `<ul>${report.anomalies_and_errors.map((item: any) => `<li>${item}</li>`).join('')}</ul>` :
                            `<p>N/A</p>`
                        }
                    </div>
                    <div class="details-card">
                        <h3>SIP/RTP Information</h3>
                        <p>${report.sip_rtp_info || 'N/A'}</p>
                    </div>
                    <div class="details-card">
                        <h3>Important Timestamps/Packets</h3>
                        <p>${report.important_timestamps_packets || 'N/A'}</p>
                    </div>
                </div>
            `;
            return html;
        }
        return "Unsupported report type.";
    }
}

// The main Worker script.
export default {
    async fetch(request: Request, env: Env): Promise<Response> {
        const url = new URL(request.url);

        // API endpoints
        if (url.pathname.startsWith("/api/analyze")) {
            // Get or create a Durable Object for this session
            const sessionId = request.headers.get("X-Session-ID") || "default";
            const id = env.ANALYSIS_OBJECT.idFromName(sessionId);
            const stub = env.ANALYSIS_OBJECT.get(id);

            // Fetch the response from the Durable Object
            return stub.fetch(request);
        }

        // Serve all other requests from the ASSETS binding
        return env.ASSETS.fetch(request);
    }
};

// Environment interface
interface Env {
    ANALYSIS_OBJECT: DurableObjectNamespace;
    ASSETS: Fetcher;
    AI: any; // Cloudflare AI binding
    config: any; // Configuration object
}