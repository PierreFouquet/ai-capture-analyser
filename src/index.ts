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
    private llmService: LLMService;

    constructor(state: DurableObjectState, env: Env) {
        this.state = state;
        this.env = env;
        this.status = 'idle';
        this.result = {};
        this.llmService = new LLMService(env);
    }

    // Handle requests to the Durable Object
    async fetch(request: Request): Promise<Response> {
        try {
            const url = new URL(request.url);
            const path = url.pathname;

            if (path.endsWith("/status")) {
                return this.handleStatusRequest();
            } else if (path.endsWith("/analyze")) {
                return await this.handleAnalyzeRequest(request);
            } else if (path.endsWith("/compare")) {
                return await this.handleCompareRequest(request);
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

    private async handleAnalyzeRequest(request: Request): Promise<Response> {
        if (this.status === 'processing') {
            return new Response("Analysis is already in progress.", { status: 409 });
        }

        try {
            const body = await request.json();
            const { pcap_data, file_name, llm_model_key } = body;
            
            if (!pcap_data || !file_name || !llm_model_key) {
                this.status = 'error';
                this.result = { error: 'Missing required parameters.' };
                await this.state.storage.put('status', 'error');
                return new Response(JSON.stringify(this.result), { status: 400 });
            }

            this.status = 'processing';
            this.result = { file_name };
            await this.state.storage.put('status', 'processing');

            // Offload the heavy lifting to a separate function
            this.processAnalysis(pcap_data, llm_model_key, file_name);

            return new Response(JSON.stringify({ status: 'started' }), { status: 202 });

        } catch (e: any) {
            this.status = 'error';
            this.result = { error: e.message };
            await this.state.storage.put('status', 'error');
            return new Response(JSON.stringify(this.result), { status: 500 });
        }
    }

    private async handleCompareRequest(request: Request): Promise<Response> {
        if (this.status === 'processing') {
            return new Response("Comparison is already in progress.", { status: 409 });
        }

        try {
            const body = await request.json();
            const { pcap_data1, pcap_data2, file_name1, file_name2, llm_model_key } = body;
            
            if (!pcap_data1 || !pcap_data2 || !file_name1 || !file_name2 || !llm_model_key) {
                this.status = 'error';
                this.result = { error: 'Missing required parameters.' };
                await this.state.storage.put('status', 'error');
                return new Response(JSON.stringify(this.result), { status: 400 });
            }

            this.status = 'processing';
            this.result = { file_name1, file_name2 };
            await this.state.storage.put('status', 'processing');

            this.processComparison(pcap_data1, pcap_data2, llm_model_key, file_name1, file_name2);

            return new Response(JSON.stringify({ status: 'started' }), { status: 202 });

        } catch (e: any) {
            this.status = 'error';
            this.result = { error: e.message };
            await this.state.storage.put('status', 'error');
            return new Response(JSON.stringify(this.result), { status: 500 });
        }
    }

    private async processAnalysis(pcap_data: string, llm_model_key: string, file_name: string) {
        try {
            const prompt = this.env.config.llm_prompts.analysis_pcap_explanation.replace(
                '{pcap_data_snippet}', `[PCAP data from ${file_name} sent as base64]`
            );

            // This is a placeholder for the actual LLM call using the Workers AI binding
            const response = await this.llmService.callLLM(llm_model_key, prompt, this.env.config.llm_prompts.analysis_pcap_explanation_schema);

            this.result.report = response;
            this.status = 'complete';
            await this.state.storage.put('status', 'complete');
            await this.state.storage.put('result', this.result);

        } catch (e: any) {
            this.status = 'error';
            this.result.error = `LLM analysis failed: ${e.message}`;
            await this.state.storage.put('status', 'error');
        }
    }

    private async processComparison(pcap_data1: string, pcap_data2: string, llm_model_key: string, file_name1: string, file_name2: string) {
        try {
            const prompt = this.env.config.llm_prompts.comparison_pcap_explanation
                .replace('{label1}', file_name1)
                .replace('{pcap_data_snippet1}', `[PCAP data from ${file_name1} sent as base64]`)
                .replace('{label2}', file_name2)
                .replace('{pcap_data_snippet2}', `[PCAP data from ${file_name2} sent as base64]`);

            const response = await this.llmService.callLLM(llm_model_key, prompt, this.env.config.llm_prompts.comparison_pcap_explanation_schema);

            this.result.report = response;
            this.status = 'complete';
            await this.state.storage.put('status', 'complete');
            await this.state.storage.put('result', this.result);

        } catch (e: any) {
            this.status = 'error';
            this.result.error = `LLM comparison failed: ${e.message}`;
            await this.state.storage.put('status', 'error');
        }
    }
}

// LLM service class to abstract the Workers AI binding
class LLMService {
    private env: Env;

    constructor(env: Env) {
        this.env = env;
    }

    async callLLM(modelKey: string, prompt: string, schema: any): Promise<any> {
        const model = this.env.config.llm_models[modelKey];
        if (!model) {
            throw new Error(`Model with key ${modelKey} not found in config.`);
        }

        const inputs = { prompt };
        
        const response = await this.env.AI.run(model.name, inputs, {
            stream: false,
            structured: {
                type: "JSON",
                schema: schema
            }
        });

        // The response from a structured AI call is the parsed JSON
        return response;
    }
}


// The main Worker script.
export default {
    async fetch(request: Request, env: Env): Promise<Response> {
        const url = new URL(request.url);

        // API endpoints
        if (url.pathname.startsWith("/api/")) {
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

// Durable Object declaration for Workers AI
export { AnalysisObject as PCAPAnalysisDurableObject };

