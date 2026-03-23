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

    async alarm() {
        console.log("6 hours of inactivity reached. Cleaning up Durable Object storage.");
        await this.state.storage.deleteAll();
        this.status = 'idle';
        this.result = null;
        this.error = null;
    }

    private async resetCleanupTimer() {
        const sixHoursFromNow = Date.now() + 6 * 60 * 60 * 1000;
        await this.state.storage.setAlarm(sixHoursFromNow);
    }

    async fetch(request: Request): Promise<Response> {
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

            // Run AI in the background. DO NOT await it here.
            this.state.waitUntil(this.executeAIAnalysis(requestBody));

            return new Response(JSON.stringify({ status: 'processing' }), {
                headers: { 'Content-Type': 'application/json' },
                status: 202 
            });

        } catch (e: any) {
            this.status = 'error';
            this.error = `Failed to start analysis: ${e.message}`;
            await this.state.storage.put({ status: this.status, result: null, error: this.error });
            return new Response(JSON.stringify({ status: this.status, error: this.error }), {
                headers: { 'Content-Type': 'application/json' },
                status: 500
            });
        }
    }

    // Background Worker Logic
    private async executeAIAnalysis(requestBody: any) {
        try {
            const { type, llm_model_key } = requestBody;

            if (!this.env.AI) throw new Error("AI binding is not available in this environment");

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
            
            try {
                response = await this.env.AI.run(llm_model_key, {
                    messages: [
                        { role: "system", content: "You are an expert network analyst. Return ONLY raw JSON matching the requested schema. Do NOT wrap it in markdown." },
                        { role: "user", content: promptToUse }
                    ],
                    max_tokens: 3000 // Expanded to allow deep reasoning models to finish
                });
            } catch (messagesError) {
                lastError = messagesError;
                try {
                    response = await this.env.AI.run(llm_model_key, { prompt: promptToUse, max_tokens: 3000 });
                } catch (promptError) {
                    lastError = promptError;
                    try {
                        response = await this.env.AI.run(llm_model_key, { input: promptToUse, max_tokens: 3000 });
                    } catch (inputError) {
                        lastError = inputError;
                        throw new Error(`All AI execution formats failed. Last error: ${lastError.message}`);
                    }
                }
            }

            if (!response) throw new Error("AI returned an empty response");

            let rawResponseStr = "";
            
            if (typeof response === 'string') {
                rawResponseStr = response;
            } else {
                if (response.response && typeof response.response === 'string') {
                    rawResponseStr = response.response;
                } else if (response.result && typeof response.result === 'string') {
                    rawResponseStr = response.result;
                } else if (response.result && response.result.response && typeof response.result.response === 'string') {
                    rawResponseStr = response.result.response;
                } else if (response.choices && response.choices.length > 0 && response.choices[0].message) {
                    rawResponseStr = String(response.choices[0].message.content);
                } else {
                    rawResponseStr = JSON.stringify(response);
                }
            }

            if (typeof rawResponseStr !== 'string') {
                rawResponseStr = String(rawResponseStr);
            }

            // Strip DeepSeek <think> blocks
            let stringToParse = rawResponseStr;
            if (stringToParse.includes('</think>')) {
                stringToParse = stringToParse.split('</think>')[1];
            } else if (stringToParse.includes('<think>')) {
                throw new Error("The AI model took too long to 'think' and hit Cloudflare's limit before generating the report. Try Llama 3.1 instead.");
            }
            
            const jsonMatch = stringToParse.match(/\{[\s\S]*\}/);
            
            if (!jsonMatch) {
                console.error("Failed to find JSON in AI response. Raw string was:", rawResponseStr);
                throw new Error("No JSON object could be extracted. The AI returned: " + rawResponseStr.substring(0, 100) + "...");
            }

            const result = JSON.parse(jsonMatch[0]);

            // Catch Llama 3.3 returning empty objects
            if (Object.keys(result).length === 0) {
                console.error("AI returned an empty JSON object. Raw string:", rawResponseStr);
                throw new Error("The AI model returned an empty report. Please try analyzing the file again or use a different model.");
            }

            this.result = result;
            this.status = 'complete';
            await this.state.storage.put({ status: this.status, result: this.result, error: null });

        } catch (e: any) {
            console.error("AI Analysis execution failed:", e);
            this.status = 'error';
            this.error = `Analysis failed: ${e.message}`;
            await this.state.storage.put({ status: this.status, result: null, error: this.error });
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
                .replace('{file_name}', data.file_name)}\n\nIMPORTANT: You must fully populate the JSON schema below with your analysis. DO NOT return an empty object. Return ONLY the raw JSON object and no other text:\n${schema}`;
        } else if (type === 'comparison') {
            const schema = JSON.stringify(llm_prompts.comparison_pcap_explanation_schema, null, 2);
            return `${llm_prompts.comparison_pcap_explanation_template
                .replace('{pcap_data_snippet1}', data.pcap_data_snippet1)
                .replace('{pcap_data_snippet2}', data.pcap_data_snippet2)
                .replace('{label1}', data.label1)
                .replace('{label2}', data.label2)}\n\nIMPORTANT: You must fully populate the JSON schema below with your comparison. DO NOT return an empty object. Return ONLY the raw JSON object and no other text:\n${schema}`;
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