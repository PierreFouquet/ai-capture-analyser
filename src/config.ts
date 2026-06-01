// Server-side configuration for the Worker / Durable Object.
//
// This file holds ONLY the prompt templates and JSON schemas, which are used
// exclusively on the server. The list of selectable models and the UI defaults
// live in public/config.js (the browser is their only consumer), so there is no
// duplication between the two files.

// llm_prompts: Prompt templates and JSON schemas for LLM interactions.
export const llm_prompts = {
    analysis_pcap_explanation_template: `
    You are an expert network and VoIP (SIP/RTP) packet analyst. The statistics below were
    extracted directly from a packet capture named "{file_name}". Base your report only on
    these figures — do not invent values that contradict them. Your response must be a JSON
    object that adheres to the provided schema.
    ---
    Capture statistics:
    {stats}
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
    You are an expert network and VoIP (SIP/RTP) packet analyst. The statistics below were
    extracted from two packet captures, labelled "{label1}" and "{label2}". Compare them,
    basing your report only on these figures. Your response must be a JSON object that adheres
    to the provided schema.
    ---
    Capture "{label1}" statistics:
    {stats1}
    ---
    Capture "{label2}" statistics:
    {stats2}
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