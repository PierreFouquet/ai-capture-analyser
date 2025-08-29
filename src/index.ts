import { llm_settings, llm_prompts } from './config';

// The Durable Object that will handle the analysis state.
export interface AnalysisObjectState {
    status: 'idle' | 'processing' | 'complete' | 'error';
    result: any;
    error?: string;
}

export class AnalysisObject {
    private state: DurableObjectState;
    private env: Env;
    private status: 'idle' | 'processing' | 'complete' | 'error';
    private result: any;
    private error: string | null = null;

    constructor(state: DurableObjectState, env: Env) {
        this.state = state;
        this.env = env;
        this.status = 'idle';
        this.result = {};

        // Load status from storage
        this.state.storage.get<AnalysisObjectState>('analysisState')
            .then(s => {
                if (s) {
                    this.status = s.status;
                    this.result = s.result;
                    this.error = s.error || null;
                }
            });
    }

    // Handle requests to the Durable Object
    async fetch(request: Request): Promise<Response> {
        const url = new URL(request.url);
        const path = url.pathname;

        try {
            if (path.endsWith("/status")) {
                return this.handleStatusRequest();
            } else if (path.endsWith("/analyze")) {
                return await this.handleProcessRequest(request);
            } else if (path.endsWith("/debug")) {
                return this.handleDebugRequest();
            } else {
                return new Response("Not Found", { status: 404 });
            }
        } catch (e: any) {
            this.status = 'error';
            this.error = e.message;
            await this.state.storage.put({ status: this.status, error: this.error, result: null });
            return new Response(JSON.stringify({ 
                status: this.status, 
                error: this.error 
            }), { 
                status: 500,
                headers: { 'Content-Type': 'application/json' }
            });
        }
    }

    private handleStatusRequest(): Response {
        return new Response(JSON.stringify({
            status: this.status,
            result: this.result,
            error: this.error,
        }), {
            headers: { 'Content-Type': 'application/json' }
        });
    }

    private handleDebugRequest(): Response {
        return new Response(JSON.stringify({
            environment: {
                AI_AVAILABLE: !!this.env.AI,
                ANALYSIS_OBJECT_AVAILABLE: !!this.env.ANALYSIS_OBJECT,
                ASSETS_AVAILABLE: !!this.env.ASSETS
            },
            status: this.status,
            hasResult: !!this.result,
            hasError: !!this.error
        }), {
            headers: { 'Content-Type': 'application/json' }
        });
    }

    private async handleProcessRequest(request: Request): Promise<Response> {
        this.status = 'processing';
        this.result = null;
        this.error = null;
        await this.state.storage.put({ status: this.status, result: null, error: null });

        try {
            const requestBody = await request.json();
            const { type, llm_model_key } = requestBody;

            // Validate that the AI binding is available
            if (!this.env.AI) {
                throw new Error("AI binding is not available in this environment");
            }

            let promptToUse;
            if (type === 'analysis') {
                const { pcap_data, file_name } = requestBody;
                const decodedData = this.b64ToArrayBuffer(pcap_data);
                const pcapSnippet = this.extractPcapSnippet(decodedData, 2048);

                // Format the prompt with the JSON schema embedded
                promptToUse = this.formatPrompt('analysis', {
                    pcap_data_snippet: pcapSnippet,
                    file_name: file_name,
                });

            } else if (type === 'comparison') {
                const { pcap_data1, pcap_data2, file_name1, file_name2 } = requestBody;
                
                const decodedData1 = this.b64ToArrayBuffer(pcap_data1);
                const pcapSnippet1 = this.extractPcapSnippet(decodedData1, 2048);
                const decodedData2 = this.b64ToArrayBuffer(pcap_data2);
                const pcapSnippet2 = this.extractPcapSnippet(decodedData2, 2048);
    
                // Format the prompt with the JSON schema embedded
                promptToUse = this.formatPrompt('comparison', {
                    pcap_data_snippet1: pcapSnippet1,
                    pcap_data_snippet2: pcapSnippet2,
                    label1: file_name1,
                    label2: file_name2,
                });
            } else {
                this.status = 'error';
                this.error = 'Invalid analysis type provided.';
                await this.state.storage.put({ status: this.status, result: null, error: this.error });
                return new Response(JSON.stringify({ status: this.status, error: this.error }), {
                    headers: { 'Content-Type': 'application/json' },
                    status: 400
                });
            }
            
            // Try different input formats with fallback
            let response;
            let lastError;
            
            // Try input format first (for models like DeepSeek, Llama, etc.)
            try {
                console.log("Trying input format for model:", llm_model_key);
                response = await this.env.AI.run(llm_model_key, {
                    input: promptToUse
                });
                console.log("Input format succeeded");
            } catch (inputError) {
                lastError = inputError;
                console.log("Input format failed:", inputError.message);
                
                // Try prompt format
                try {
                    console.log("Trying prompt format for model:", llm_model_key);
                    response = await this.env.AI.run(llm_model_key, {
                        prompt: promptToUse
                    });
                    console.log("Prompt format succeeded");
                } catch (promptError) {
                    lastError = promptError;
                    console.log("Prompt format failed:", promptError.message);
                    
                    // Try messages format (for OpenAI-compatible models)
                    try {
                        console.log("Trying messages format for model:", llm_model_key);
                        response = await this.env.AI.run(llm_model_key, {
                            messages: [
                                {
                                    role: "user",
                                    content: promptToUse
                                }
                            ]
                        });
                        console.log("Messages format succeeded");
                    } catch (messagesError) {
                        lastError = messagesError;
                        console.log("Messages format failed:", messagesError.message);
                        
                        // Try a simple text format as a last resort
                        try {
                            console.log("Trying text format for model:", llm_model_key);
                            response = await this.env.AI.run(llm_model_key, {
                                text: promptToUse
                            });
                            console.log("Text format succeeded");
                        } catch (textError) {
                            lastError = textError;
                            console.log("Text format failed:", textError.message);
                            throw new Error(`All input formats failed. Last error: ${lastError.message}`);
                        }
                    }
                }
            }

            // Check if response is empty or undefined
            if (!response) {
                throw new Error("AI returned an empty response");
            }

            // Parse the response from the AI model
            let result;
            try {
                // Cloudflare AI returns the response in different formats depending on the model
                if (typeof response === 'string') {
                    // Try to parse as JSON first
                    try {
                        result = JSON.parse(response);
                    } catch (e) {
                        // If it's not JSON, try to extract JSON from the string
                        const jsonMatch = response.match(/\{[\s\S]*\}|\[[\s\S]*\]/);
                        if (jsonMatch) {
                            result = JSON.parse(jsonMatch[0]);
                        } else {
                            // If no JSON found, use the raw response
                            result = { raw_response: response };
                        }
                    }
                } else if (response.response) {
                    result = typeof response.response === 'string' ? JSON.parse(response.response) : response.response;
                } else if (response.result) {
                    result = typeof response.result === 'string' ? JSON.parse(response.result) : response.result;
                } else if (response.choices && response.choices.length > 0) {
                    // Some models return choices array (like OpenAI-compatible models)
                    const choice = response.choices[0];
                    if (choice.message && choice.message.content) {
                        try {
                            result = JSON.parse(choice.message.content);
                        } catch (e) {
                            result = { raw_response: choice.message.content };
                        }
                    } else if (choice.text) {
                        try {
                            result = JSON.parse(choice.text);
                        } catch (e) {
                            result = { raw_response: choice.text };
                        }
                    } else {
                        result = response;
                    }
                } else if (response.message && response.message.content) {
                    // Some models return a single message object
                    try {
                        result = JSON.parse(response.message.content);
                    } catch (e) {
                        result = { raw_response: response.message.content };
                    }
                } else {
                    // If all else fails, try to stringify and parse
                    try {
                        const responseString = JSON.stringify(response);
                        result = JSON.parse(responseString);
                    } catch (e) {
                        console.error("Failed to parse AI response as JSON:", response);
                        result = { raw_response: response };
                    }
                }
            } catch (e) {
                console.error("Failed to parse AI response:", response);
                // If parsing fails, return the raw response for debugging
                result = { raw_response: response, error: "Failed to parse response as JSON" };
            }

            // Validate that we have a proper result
            if (!result || (typeof result === 'object' && Object.keys(result).length === 0)) {
                throw new Error("AI returned an empty or invalid result");
            }

            this.result = result;
            this.status = 'complete';
            await this.state.storage.put({ status: this.status, result: this.result, error: null });

            return new Response(JSON.stringify({ status: this.status, result: this.result }), {
                headers: { 'Content-Type': 'application/json' }
            });

        } catch (e: any) {
            this.status = 'error';
            this.error = `Analysis failed: ${e.message}`;
            await this.state.storage.put({ status: this.status, result: null, error: this.error });
            return new Response(JSON.stringify({ status: this.status, error: this.error }), {
                headers: { 'Content-Type': 'application/json' },
                status: 500
            });
        }
    }

    // Helper function to decode Base64 string to ArrayBuffer
    private b64ToArrayBuffer(base64: string): ArrayBuffer {
        const binaryString = atob(base64);
        const len = binaryString.length;
        const bytes = new Uint8Array(len);
        for (let i = 0; i < len; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }
        return bytes.buffer;
    }

    // Helper to extract a small snippet from the data
    private extractPcapSnippet(buffer: ArrayBuffer, size: number): string {
        const bytes = new Uint8Array(buffer);
        const snippet = bytes.slice(0, size);
        return Array.from(snippet).map(byte => byte.toString(16).padStart(2, '0')).join('');
    }

    // Helper to format the prompt based on the type, with JSON schema instructions
    private formatPrompt(type: 'analysis' | 'comparison', data: any): string {
        if (type === 'analysis') {
            const schema = JSON.stringify(llm_prompts.analysis_pcap_explanation_schema, null, 2);
            return `${llm_prompts.analysis_pcap_explanation_template
                .replace('{pcap_data_snippet}', data.pcap_data_snippet)
                .replace('{file_name}', data.file_name)}\n\nIMPORTANT: Respond with ONLY a single JSON object that strictly adheres to the following schema. DO NOT include any other text, explanations, or code block markers (like \`\`\`json\`\`\`): \n${schema}`;
        } else if (type === 'comparison') {
            const schema = JSON.stringify(llm_prompts.comparison_pcap_explanation_schema, null, 2);
            return `${llm_prompts.comparison_pcap_explanation_template
                .replace('{pcap_data_snippet1}', data.pcap_data_snippet1)
                .replace('{pcap_data_snippet2}', data.pcap_data_snippet2)
                .replace('{label1}', data.label1)
                .replace('{label2}', data.label2)}\n\nIMPORTANT: Respond with ONLY a single JSON object that strictly adheres to the following schema. DO NOT include any other text, explanations, or code block markers (like \`\`\`json\`\`\`): \n${schema}`;
        }
        return '';
    }
}

// The main Worker script.
export default {
    async fetch(request: Request, env: Env): Promise<Response> {
        const url = new URL(request.url);

        // API endpoint for Durable Object
        if (url.pathname.startsWith("/api/analyze")) {
            // Get or create a Durable Object for this session
            const sessionId = request.headers.get("X-Session-ID") || "default";
            const id = env.ANALYSIS_OBJECT.idFromName(sessionId);
            const stub = env.ANALYSIS_OBJECT.get(id);

            // Fetch the response from the Durable Object
            return stub.fetch(request);
        }

        // Debug endpoint
        if (url.pathname.startsWith("/api/debug")) {
            const sessionId = request.headers.get("X-Session-ID") || "default";
            const id = env.ANALYSIS_OBJECT.idFromName(sessionId);
            const stub = env.ANALYSIS_OBJECT.get(id);
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