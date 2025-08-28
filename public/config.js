// This file contains the configuration for the application.

// llm_models: A list of available LLM models.
export const llm_models = {
    // Cloudflare Workers AI Models
    "@cf/openai/gpt-oss-120b": {
        name: "GPT OSS 120b",
        provider: "Cloudflare"
    },
    "@cf/openai/gpt-oss-20b": {
        name: "GPT OSS 20b",
        provider: "Cloudflare"
    },
    "@cf/deepseek-ai/deepseek-r1-distill-qwen-32b": {
        name: "DeepSeek R1 Distill Qwen 32B",
        provider: "Cloudflare"
    },
    "@cf/deepseek-ai/deepseek-math-7b-instruct": {
        name: "DeepSeek Math Instruct 7B",
        provider: "Cloudflare"
    },
    "@cf/microsoft/phi-2": {
        name: "Microsoft Phi-2",
        provider: "Cloudflare"
    },
    "@cf/google/gemma-7b-it": {
        name: "Google Gemma 7b",
        provider: "Cloudflare"
    },
    "@cf/google/gemma-3-12b-it": {
        name: "Google Gemma 3 12b",
        provider: "Cloudflare"
    },
    "@cf/meta/llama-4-scout-17b-16e-instruct": {
        name: "Meta Llama 4 Scout",
        provider: "Cloudflare"
    },
    "@cf/mistral/mistral-7b-instruct-v0.2": {
        name: "Mistral 7b Instruct",
        provider: "Cloudflare"
    },
    "@cf/qwen/qwen-1.8b-chat": {
        name: "Qwen 1.8b Chat",
        provider: "Cloudflare"
    },
    "@cf/openchat/openchat-3.5-0106": {
        name: "OpenChat 3.5",
        provider: "Cloudflare"
    },
    "@cf/tiiuae/falcon-7b-instruct": {
        name: "Falcon 7b Instruct",
        provider: "Cloudflare"
    },
    "@cf/google/gemma-2-9b-it": {
        name: "Google Gemma 2 9b",
        provider: "Cloudflare"
    },
    "@cf/llama-4-scout-17b-16e-instruct": {
        name: "Llama 4 Scout",
        provider: "Cloudflare"
    },
};

// llm_settings: Global LLM settings
export const llm_settings = {
    default_llm_model_analysis: "@cf/deepseek-ai/deepseek-r1-distill-qwen-32b",
    default_llm_model_comparison: "@cf/deepseek-ai/deepseek-r1-distill-qwen-32b",
    // Note: async_mode_enabled is for the Python backend, not relevant for this JS/TS app
};

// llm_prompts: Prompt templates and JSON schemas for LLM interactions.
export const llm_prompts = {
    analysis_pcap_explanation_template: `
    You are an expert SIP and RTP packet analyst. Your task is to analyze a raw PCAP file snippet and provide a detailed report.
    The user will provide a snippet of raw PCAP data.
    Your response must be a JSON object that adheres to the provided schema.
    ---
    PCAP Snippet ({file_name}):
    {pcap_data_snippet}
    `,
    analysis_pcap_explanation_schema: {
        type: "object",
        properties: {
            summary: {
                type: "string",
                description: "Overall summary of the network traffic, including key protocols, services, and traffic patterns."
            },
            protocol_distribution: {
                type: "object",
                patternProperties: {
                    ".*": { "type": "number" }
                },
                description: "A key-value pair of protocol names and their percentage distribution in the capture."
            },
            anomalies_and_errors: {
                type: "array",
                items: {
                    type: "string"
                },
                description: "List of detected anomalies or errors, such as unusual traffic, failed connections, or potential security threats."
            },
            sip_rtp_info: {
                type: "string",
                description: "Summary of any detected SIP/RTP information, otherwise 'N/A'."
            },
            important_timestamps_packets: {
                type: "string",
                description: "Key timestamps or packet numbers, otherwise 'N/A'."
            }
        },
        required: ["summary", "protocol_distribution", "anomalies_and_errors", "sip_rtp_info", "important_timestamps_packets"]
    },

    comparison_pcap_explanation_template: `
    You are an expert SIP and RTP packet analyst. Your task is to compare two raw PCAP file snippets.
    The user will provide two snippets of raw PCAP data, labeled {label1} and {label2}.
    Your response must be a JSON object that adheres to the provided schema.
    ---
    PCAP 1 Snippet ({label1}):
    {pcap_data_snippet1}
    ---
    PCAP 2 Snippet ({label2}):
    {pcap_data_snippet2}
    `,
    comparison_pcap_explanation_schema: {
        type: "object",
        properties: {
            overall_comparison_summary: {
                type: "string",
                description: "Overall summary of the comparison."
            },
            key_differences: {
                type: "array",
                items: {
                    type: "string"
                },
                description: "List of key differences between the two captures."
            },
            key_similarities: {
                type: "array",
                items: {
                    type: "string"
                },
                description: "List of key similarities between the two captures."
            },
            security_implications: {
                type: "array",
                items: {
                    type: "string"
                },
                description: "Analysis of any security implications or risks identified."
            },
            important_timestamps_packets: {
                type: "string",
                description: "Key timestamps or packet numbers relevant to the comparison, otherwise 'N/A'."
            }
        },
        required: ["overall_comparison_summary", "key_differences", "key_similarities", "security_implications", "important_timestamps_packets"]
    },
};

// Make the configuration available globally
pcapAnalyzerConfig = { llm_models, llm_settings, llm_prompts };