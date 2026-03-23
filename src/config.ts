// This file contains the configuration for the application.

// llm_models: A list of available LLM models.
export const llm_models = {
    // Top Tier Reasoning & Analysis
    "@cf/meta/llama-3.3-70b-instruct-fp8-fast": {
        name: "Meta Llama 3.3 (70B) - Highly Recommended",
        provider: "Cloudflare"
    },
    "@cf/deepseek-ai/deepseek-r1-distill-qwen-32b": {
        name: "DeepSeek R1 Distill Qwen 32B",
        provider: "Cloudflare"
    },
    // Fast & Efficient 
    "@cf/meta/llama-3.1-8b-instruct": {
        name: "Meta Llama 3.1 (8B)",
        provider: "Cloudflare"
    },
    "@cf/google/gemma-2-9b-it": {
        name: "Google Gemma 2 (9B)",
        provider: "Cloudflare"
    },
    // Legacy / Specialized
    "@cf/qwen/qwen1.5-14b-chat-awq": {
        name: "Qwen 1.5 (14B)",
        provider: "Cloudflare"
    },
    "@cf/mistral/mistral-7b-instruct-v0.2": {
        name: "Mistral 7b Instruct",
        provider: "Cloudflare"
    }
};

// llm_settings: Global LLM settings
export const llm_settings = {
    // Cloudflare AI settings - these vary by model
    // For text generation models, we typically don't need additional settings
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