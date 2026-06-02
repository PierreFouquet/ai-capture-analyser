// How long to keep polling before giving up, and how often to poll.
const MAX_POLL_MS = 5 * 60 * 1000; // 5 minutes
const POLL_INTERVAL_MS = 1000;

// This file handles all communication with the backend API
export class Backend {
    constructor() {
        this.sessionId = this.generateSessionId();
    }

    generateSessionId() {
        // Generate a unique session ID to keep track of analysis requests
        return 'session-' + Date.now() + '-' + Math.random().toString(36).substring(2, 9);
    }

    // Send a request to the analyse endpoint and poll for the result. Only the
    // aggregated capture statistics are sent — never the raw packet bytes.
    async submitAndPoll(payload, failurePrefix) {
        try {
            const response = await fetch('/api/analyze', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Session-ID': this.sessionId,
                },
                body: JSON.stringify(payload),
            });

            const responseData = await response.json();

            if (!response.ok) {
                throw new Error(responseData.error || `Server responded with status ${response.status}`);
            }

            return this.pollStatus('/api/analyze/status');
        } catch (error) {
            console.error('API call failed:', error);
            throw new Error(`${failurePrefix}: ${error.message}`);
        }
    }

    async analyzePcap(summary, fileName, llmModelKey) {
        return this.submitAndPoll(
            {
                type: 'analysis',
                pcap_summary: summary,
                file_name: fileName,
                llm_model_key: llmModelKey,
            },
            'Analysis failed'
        );
    }

    async comparePcaps(summary1, fileName1, summary2, fileName2, llmModelKey) {
        return this.submitAndPoll(
            {
                type: 'comparison',
                pcap_summary1: summary1,
                file_name1: fileName1,
                pcap_summary2: summary2,
                file_name2: fileName2,
                llm_model_key: llmModelKey,
            },
            'Comparison failed'
        );
    }

    // Function to poll the status of the analysis job
    pollStatus(statusUrl) {
        return new Promise((resolve, reject) => {
            const startedAt = Date.now();
            let inFlight = false; // prevent overlapping requests if a poll is slow

            const pollInterval = setInterval(async () => {
                // Give up rather than spin forever on a stuck/processing job.
                if (Date.now() - startedAt >= MAX_POLL_MS) {
                    clearInterval(pollInterval);
                    reject(new Error('Analysis timed out. Please try again, or use a faster model.'));
                    return;
                }
                if (inFlight) return; // skip this tick; the previous request is still running
                inFlight = true;
                try {
                    const statusResponse = await fetch(statusUrl, {
                        headers: { 'X-Session-ID': this.sessionId }
                    });

                    if (!statusResponse.ok) {
                        throw new Error(`Status check failed: ${statusResponse.status}`);
                    }

                    const result = await statusResponse.json();

                    if (result.status === 'complete') {
                        clearInterval(pollInterval);
                        resolve(result.result);
                    } else if (result.status === 'error') {
                        clearInterval(pollInterval);
                        reject(new Error(result.error || 'An unknown error occurred during analysis.'));
                    }
                    // If status is 'processing', continue polling
                } catch (error) {
                    clearInterval(pollInterval);
                    reject(error);
                } finally {
                    inFlight = false;
                }
            }, POLL_INTERVAL_MS);
        });
    }

    // Debug function to check the environment
    async debug() {
        try {
            const response = await fetch('/api/debug', {
                headers: { 'X-Session-ID': this.sessionId }
            });
            
            if (!response.ok) {
                throw new Error(`Debug check failed: ${response.status}`);
            }
            
            return await response.json();
        } catch (error) {
            console.error('Debug failed:', error);
            throw error;
        }
    }
}