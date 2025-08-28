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
            } else if (path.endsWith("/process")) {
                return await this.handleProcessRequest(request);
            } else if (path.endsWith("/compare-process")) {
                return await this.handleCompareRequest(request);
            } else {
                return new Response("Not Found", { status: 404 });
            }
        } catch (e: any) {
            this.status = 'error';
            this.error = e.message;
            await this.state.storage.put({ status: this.status, error: this.error, result: null });
            return new Response(`An error occurred: ${e.message}`, { status: 500 });
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

    private async handleProcessRequest(request: Request): Promise<Response> {
        this.status = 'processing';
        this.result = null;
        this.error = null;
        await this.state.storage.put({ status: this.status, result: null, error: null });

        try {
            const requestBody = await request.json();
            const { pcap_data, file_name, llm_model_key } = requestBody;

            // Simulate parsing the PCAP data
            const decodedData = this.b64ToArrayBuffer(pcap_data);
            const pcapSnippet = this.extractPcapSnippet(decodedData, 2048);

            // Use Cloudflare Workers AI to generate the analysis
            const response = await this.env.AI.run(llm_model_key, {
                prompt: this.formatPrompt('analysis', {
                    pcap_data_snippet: pcapSnippet,
                    file_name: file_name,
                }),
                ...llm_settings,
                prompt_schema: llm_prompts.analysis_pcap_schema
            });

            this.result = response;
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
                headers: { 'Content-Type': 'application/json' }
            });
        }
    }

    private async handleCompareRequest(request: Request): Promise<Response> {
        this.status = 'processing';
        this.result = null;
        this.error = null;
        await this.state.storage.put({ status: this.status, result: null, error: null });

        try {
            const requestBody = await request.json();
            const { pcap_data1, pcap_data2, file_name1, file_name2, llm_model_key } = requestBody;

            // Simulate parsing and extracting snippets
            const decodedData1 = this.b64ToArrayBuffer(pcap_data1);
            const pcapSnippet1 = this.extractPcapSnippet(decodedData1, 2048);
            const decodedData2 = this.b64ToArrayBuffer(pcap_data2);
            const pcapSnippet2 = this.extractPcapSnippet(decodedData2, 2048);

            // Use Cloudflare Workers AI to generate the comparison
            const response = await this.env.AI.run(llm_model_key, {
                prompt: this.formatPrompt('comparison', {
                    pcap_data_snippet1: pcapSnippet1,
                    pcap_data_snippet2: pcapSnippet2,
                    label1: file_name1,
                    label2: file_name2,
                }),
                ...llm_settings,
                prompt_schema: llm_prompts.comparison_pcap_explanation_schema
            });

            this.result = response;
            this.status = 'complete';
            await this.state.storage.put({ status: this.status, result: this.result, error: null });

            return new Response(JSON.stringify({ status: this.status, result: this.result }), {
                headers: { 'Content-Type': 'application/json' }
            });
        } catch (e: any) {
            this.status = 'error';
            this.error = `Comparison failed: ${e.message}`;
            await this.state.storage.put({ status: this.status, result: null, error: this.error });
            return new Response(JSON.stringify({ status: this.status, error: this.error }), {
                headers: { 'Content-Type': 'application/json' }
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

    // Helper to format the prompt based on the type
    private formatPrompt(type: 'analysis' | 'comparison', data: any): string {
        if (type === 'analysis') {
            return llm_prompts.analysis_pcap_explanation_prompt
                .replace('{pcap_data_snippet}', data.pcap_data_snippet)
                .replace('{file_name}', data.file_name);
        } else if (type === 'comparison') {
            return llm_prompts.comparison_pcap_explanation_prompt
                .replace('{pcap_data_snippet1}', data.pcap_data_snippet1)
                .replace('{pcap_data_snippet2}', data.pcap_data_snippet2)
                .replace('{label1}', data.label1)
                .replace('{label2}', data.label2);
        }
        return '';
    }
}

// The main Worker script.
export default {
    async fetch(request: Request, env: Env): Promise<Response> {
        const url = new URL(request.url);

        // API endpoints for Durable Objects
        if (url.pathname.startsWith("/api/analyze")) {
            // Get or create a Durable Object for this session
            const sessionId = request.headers.get("X-Session-ID") || "default";
            const id = env.ANALYSIS_OBJECT.idFromName(sessionId);
            const stub = env.ANALYSIS_OBJECT.get(id);

            // Fetch the response from the Durable Object
            return stub.fetch(request);
        }
        if (url.pathname.startsWith("/api/compare")) {
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
