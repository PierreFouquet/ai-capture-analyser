import { formatPrompt, parseModelResponse } from './analysis';

const STATE_KEY = 'analysisState';
const MAX_TOKENS = 8000; // Headroom for reasoning models that "think" before answering.

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
            const s = await this.state.storage.get<AnalysisObjectState>(STATE_KEY);
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

    // Persist the current state under a single key so the constructor can restore it.
    private async persistState(): Promise<void> {
        const snapshot: AnalysisObjectState = {
            status: this.status,
            result: this.result,
            error: this.error ?? undefined,
        };
        await this.state.storage.put(STATE_KEY, snapshot);
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
            this.result = null;
            await this.persistState();
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
        await this.persistState();

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
                const { pcap_summary, file_name } = requestBody;
                if (!pcap_summary) throw new Error("Missing capture statistics in request.");
                promptToUse = formatPrompt('analysis', { fileName: file_name, summary: pcap_summary });
            } else if (type === 'comparison') {
                const { pcap_summary1, pcap_summary2, file_name1, file_name2 } = requestBody;
                if (!pcap_summary1 || !pcap_summary2) throw new Error("Missing capture statistics in request.");
                promptToUse = formatPrompt('comparison', {
                    label1: file_name1,
                    label2: file_name2,
                    summary1: pcap_summary1,
                    summary2: pcap_summary2,
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
                    max_tokens: MAX_TOKENS
                });
            } catch (messagesError) {
                lastError = messagesError;
                try {
                    response = await this.env.AI.run(llm_model_key, { prompt: promptToUse, max_tokens: MAX_TOKENS });
                } catch (promptError) {
                    lastError = promptError;
                    try {
                        response = await this.env.AI.run(llm_model_key, { input: promptToUse, max_tokens: MAX_TOKENS });
                    } catch (inputError) {
                        lastError = inputError;
                        throw new Error(`All AI execution formats failed. Last error: ${(lastError as Error).message}`);
                    }
                }
            }

            if (!response) throw new Error("AI returned an empty response");

            this.result = parseModelResponse(response);
            this.status = 'complete';
            this.error = null;
            await this.persistState();

        } catch (e: any) {
            console.error("AI Analysis execution failed:", e);
            this.status = 'error';
            this.result = null;
            this.error = `Analysis failed: ${e.message}`;
            await this.persistState();
        }
    }
}

export default {
    async fetch(request: Request, env: Env): Promise<Response> {
        const url = new URL(request.url);

        if (url.pathname.startsWith("/api/analyze") || url.pathname.startsWith("/api/debug")) {
            const sessionId = request.headers.get("X-Session-ID") || "default";
            const id = env.ANALYSIS_OBJECT.idFromName(sessionId);

            // 'weur' (Western Europe) keeps the DO's storage and processing close to
            // the UK, matching the targeted placement region in wrangler.toml.
            const stub = env.ANALYSIS_OBJECT.get(id, { locationHint: 'weur' });

            return stub.fetch(request);
        }

        return env.ASSETS.fetch(request);
    }
};

interface Env {
    ANALYSIS_OBJECT: DurableObjectNamespace;
    ASSETS: Fetcher;
    // The Workers AI binding. Typed loosely because the model key is chosen at
    // runtime, which the strongly-per-model `Ai` type does not accommodate.
    AI: {
        run(model: string, inputs: Record<string, unknown>, options?: Record<string, unknown>): Promise<unknown>;
    };
}