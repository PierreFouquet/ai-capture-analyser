// Server-side configuration for the Worker / Durable Object.
//
// This file holds ONLY the prompt templates and JSON schemas, which are used
// exclusively on the server. The list of selectable models and the UI defaults
// live in public/config.js (the browser is their only consumer), so there is no
// duplication between the two files.

// A reusable schema fragment: the model's diagnosis of problems seen in the
// traffic, each with a likely cause and a concrete suggested fix.
const issues_and_recommendations_schema = {
    type: "array",
    items: {
        type: "object",
        properties: {
            issue: { type: "string", description: "The error or problem observed in the traffic." },
            likely_cause: { type: "string", description: "The most probable root cause, grounded in the figures." },
            suggested_resolution: { type: "string", description: "A concrete, actionable fix or next step." }
        },
        required: ["issue", "likely_cause", "suggested_resolution"]
    },
    description: "Problems detected in the capture (e.g. TCP resets, failed handshakes, one-way audio, DNS failures), each with its likely cause and a suggested resolution. Empty array if none."
};

// llm_prompts: Prompt templates and JSON schemas for LLM interactions.
export const llm_prompts = {
    analysis_pcap_explanation_template: `
    You are an expert network and VoIP (SIP/RTP) packet analyst. The statistics below were
    extracted directly from a packet capture named "{file_name}". Base your report ONLY on
    these figures — never invent values that contradict them; if a figure is absent, say so
    rather than guessing.

    Analyse the capture thoroughly and cover:
    - Overall traffic: the dominant protocols, services and what the hosts appear to be doing.
    - Top talkers and conversations: which endpoints are busiest and what that implies.
    - TCP connection health: interpret the SYN / SYN-ACK / FIN / RST counts. Many RSTs or
      SYNs without matching SYN-ACKs suggest refused/failed connections or scanning; a healthy
      mix of SYN→SYN-ACK→FIN suggests normal sessions.
    - Throughput and packet sizes: comment on whether the rate and sizes look normal for the
      protocol mix (e.g. tiny packets dominating, or unusually high bitrate).
    - Security concerns: port scans, unexpected ports, plaintext services, or suspicious peers.
    - VoIP (if SIP/RTP present): assess call setup and likely media/call-quality from the
      stream and packet counts.
    For every problem you identify, record it in "issues_and_recommendations" with a likely
    cause and a concrete suggested resolution.

    Your response must be a JSON object that adheres to the provided schema.
    ---
    Capture statistics:
    {stats}
    `,
    analysis_pcap_explanation_schema: {
        type: "object",
        properties: {
            summary: {
                type: "string",
                description: "Overall summary of the network traffic, including key protocols, services, top talkers, and traffic patterns."
            },
            protocol_distribution: {
                type: "object",
                patternProperties: {
                    ".*": { "type": "number" }
                },
                description: "A key-value pair of protocol names and their percentage distribution in the capture."
            },
            traffic_health: {
                type: "string",
                description: "Assessment of connection health and throughput: TCP handshake/reset behaviour, retransmission/failure signs, and whether the rate and packet sizes look normal."
            },
            security_assessment: {
                type: "string",
                description: "Security-focused assessment: scans, unexpected ports, plaintext or risky services, and suspicious endpoints. 'No notable concerns' if none."
            },
            anomalies_and_errors: {
                type: "array",
                items: {
                    type: "string"
                },
                description: "List of detected anomalies or errors, such as unusual traffic, failed connections, or potential security threats."
            },
            issues_and_recommendations: issues_and_recommendations_schema,
            sip_rtp_info: {
                type: "string",
                description: "Summary of any detected SIP/RTP information, otherwise 'N/A'."
            },
            important_timestamps_packets: {
                type: "string",
                description: "Key timestamps or packet numbers, otherwise 'N/A'."
            }
        },
        required: ["summary", "protocol_distribution", "traffic_health", "security_assessment", "anomalies_and_errors", "issues_and_recommendations", "sip_rtp_info", "important_timestamps_packets"]
    },

    comparison_pcap_explanation_template: `
    You are an expert network and VoIP (SIP/RTP) packet analyst. The statistics below were
    extracted from two packet captures, labelled "{label1}" and "{label2}". Compare them,
    basing your report ONLY on these figures.

    In your comparison, pay attention to: shifts in the protocol mix, top talkers and
    conversations, TCP connection health (changes in SYN / SYN-ACK / FIN / RST behaviour that
    indicate new failures, resets or scanning), throughput and packet-size differences, and any
    new or resolved security concerns. For every problem evident in either capture, record it in
    "issues_and_recommendations" with a likely cause and a concrete suggested resolution.

    Your response must be a JSON object that adheres to the provided schema.
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
            issues_and_recommendations: issues_and_recommendations_schema,
            important_timestamps_packets: {
                type: "string",
                description: "Key timestamps or packet numbers relevant to the comparison, otherwise 'N/A'."
            }
        },
        required: ["overall_comparison_summary", "key_differences", "key_similarities", "security_implications", "issues_and_recommendations", "important_timestamps_packets"]
    },
};