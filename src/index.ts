import { llm_settings, llm_prompts } from './config';

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

        this.state.blockConcurrencyWhile(async () => {
            const s = await this.state.storage.get<AnalysisObjectState>('analysisState');
            if (s) {
                this.status = s.status;
                this.result = s.result;
                this.error = s.error || null;
            }
        });
    }

    // This triggers automatically when the alarm goes off (6 hours after last use)
    async alarm() {
        console.log("6 hours of inactivity reached. Cleaning up Durable Object storage.");
        await this.state.storage.deleteAll();
        this.status = 'idle';
        this.result = null;
        this.error = null;
    }

    // Helper to reset the 6-hour cleanup timer on every interaction
    private async resetCleanupTimer() {
        const sixHoursFromNow = Date.now() + 6 * 60 * 60 * 1000;
        await this.state.storage.setAlarm(sixHoursFromNow);
    }

    async fetch(request: Request): Promise<Response> {
        // Reset the 6-hour deletion timer every time the object is accessed
        await this.resetCleanupTimer();

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
            return new Response(JSON.stringify({ status: this.status, error: this.error }), { 
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

            if (!this.env.AI) {
                throw new Error("AI binding is not available in this environment");
            }

            let promptToUse;
            if (type === 'analysis') {
                const { pcap_data, file_name } = requestBody;
                const decodedData = this.b64ToArrayBuffer(pcap_data);
                const pcapSnippet = this.extractPcapSnippet(decodedData, 2048);
                promptToUse = this.formatPrompt('analysis', { pcap_data_snippet: pcapSnippet, file_name: file_name });
            } else if (type === 'comparison') {
                const { pcap_data1, pcap_data2, file_name1, file_name2 } = requestBody;
                const decodedData1 = this.b64ToArrayBuffer(pcap_data1);
                const pcapSnippet1 = this.extractPcapSnippet(decodedData1, 2048);
                const decodedData2 = this.b64ToArrayBuffer(pcap_data2);
                const pcapSnippet2 = this.extractPcapSnippet(decodedData2, 2048);
                promptToUse = this.formatPrompt('comparison', {
                    pcap_data_snippet1: pcapSnippet1, pcap_data_snippet2: pcapSnippet2,
                    label1: file_name1, label2: file_name2,
                });
            } else {
                throw new Error("Invalid analysis type provided.");
            }
            
            let response;
            let lastError;
            
            // ✅ FIX: Try `messages` format FIRST. Modern CF models strictly require this.
            try {
                console.log("Trying messages format for model:", llm_model_key);
                response = await this.env.AI.run(llm_model_key, {
                    messages: [
                        { role: "system", content: "You are an expert network analyst. Return ONLY raw JSON matching the requested schema." },
                        { role: "user", content: promptToUse }
                    ]
                });
            } catch (messagesError) {
                lastError = messagesError;
                console.log("Messages format failed, trying prompt format...");
                
                try {
                    response = await this.env.AI.run(llm_model_key, { prompt: promptToUse });
                } catch (promptError) {
                    lastError = promptError;
                    console.log("Prompt format failed, trying input format...");
                    
                    try {
                        response = await this.env.AI.run(llm_model_key, { input: promptToUse });
                    } catch (inputError) {
                        lastError = inputError;
                        throw new Error(`All AI execution formats failed. Last error: ${lastError.message}`);
                    }
                }
            }

            if (!response) throw new Error("AI returned an empty response");

            let result;
            try {
                // Handle different response structures from different models
                let rawResponseStr = "";
                if (typeof response === 'string') rawResponseStr = response;
                else if (response.response) rawResponseStr = response.response;
                else if (response.result) rawResponseStr = response.result;
                else if (response.choices && response.choices.length > 0 && response.choices[0].message) {
                    rawResponseStr = response.choices[0].message.content;
                }
                
                // Clean up any markdown formatting the AI might have wrapped the JSON in
                rawResponseStr = rawResponseStr.replace(/```json/g, '').replace(/```/g, '').trim();
                result = JSON.parse(rawResponseStr);

            } catch (e) {
                console.error("Failed to parse AI response as JSON:", response);
                result = { raw_response: response, error: "Failed to parse response as JSON" };
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

    private b64ToArrayBuffer(base64: string): ArrayBuffer {
        const binaryString = atob(base64);
        const len = binaryString.length;
        const bytes = new Uint8Array(len);
        for (let i = 0; i < len; i++) bytes[i] = binaryString.charCodeAt(i);
        return bytes.buffer;
    }

    private extractPcapSnippet(buffer: ArrayBuffer, size: number): string {
        const bytes = new Uint8Array(buffer);
        const snippet = bytes.slice(0, size);
        return Array.from(snippet).map(byte => byte.toString(16).padStart(2, '0')).join('');
    }

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

export default {
    async fetch(request: Request, env: Env): Promise<Response> {
        const url = new URL(request.url);

        if (url.pathname.startsWith("/api/analyze") || url.pathname.startsWith("/api/debug")) {
            const sessionId = request.headers.get("X-Session-ID") || "default";
            const id = env.ANALYSIS_OBJECT.idFromName(sessionId);
            const stub = env.ANALYSIS_OBJECT.get(id);
            return stub.fetch(request);
        }

        return env.ASSETS.fetch(request);
    }
};

interface Env {
    ANALYSIS_OBJECT: DurableObjectNamespace;
    ASSETS: Fetcher;
    AI: any; 
    config: any;
}