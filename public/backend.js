// This file handles all communication with the backend API
export class Backend {
    constructor() {
        this.sessionId = this.generateSessionId();
    }

    generateSessionId() {
        // Generate a unique session ID to keep track of analysis requests
        return 'session-' + Date.now() + '-' + Math.random().toString(36).substring(2, 9);
    }

    async analyzePcap(file, llmModelKey) {
        // Read the file as an ArrayBuffer
        const arrayBuffer = await file.arrayBuffer();
        // Convert the ArrayBuffer to a Base64 string for transmission
        const base64PcapData = btoa(String.fromCharCode(...new Uint8Array(arrayBuffer)));

        try {
            const response = await fetch('/api/analyze/process', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Session-ID': this.sessionId
                },
                body: JSON.stringify({
                    pcap_data: base64PcapData,
                    file_name: file.name,
                    llm_model_key: llmModelKey,
                }),
            });

            if (!response.ok) {
                const errorResult = await response.json();
                throw new Error(errorResult.error || `Server responded with status ${response.status}`);
            }

            // Start polling the status endpoint to get the final result
            return this.pollStatus('/api/analyze/status');
        } catch (error) {
            console.error('API call failed:', error);
            throw error;
        }
    }

    async comparePcaps(file1, file2, llmModelKey) {
        const arrayBuffer1 = await file1.arrayBuffer();
        const base64PcapData1 = btoa(String.fromCharCode(...new Uint8Array(arrayBuffer1)));

        const arrayBuffer2 = await file2.arrayBuffer();
        const base64PcapData2 = btoa(String.fromCharCode(...new Uint8Array(arrayBuffer2)));
        
        try {
            const response = await fetch('/api/compare/process', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Session-ID': this.sessionId
                },
                body: JSON.stringify({
                    pcap_data1: base64PcapData1,
                    file_name1: file1.name,
                    pcap_data2: base64PcapData2,
                    file_name2: file2.name,
                    llm_model_key: llmModelKey,
                }),
            });

            if (!response.ok) {
                const errorResult = await response.json();
                throw new Error(errorResult.error || `Server responded with status ${response.status}`);
            }

            // Start polling the status endpoint to get the final result
            return this.pollStatus('/api/compare/status');
        } catch (error) {
            console.error('API call failed:', error);
            throw error;
        }
    }

    // Function to poll the status of the analysis job
    pollStatus(statusUrl) {
        return new Promise((resolve, reject) => {
            const pollInterval = setInterval(async () => {
                try {
                    const statusResponse = await fetch(statusUrl, {
                        headers: { 'X-Session-ID': this.sessionId }
                    });
                    const result = await statusResponse.json();

                    if (result.status === 'complete') {
                        clearInterval(pollInterval);
                        resolve(result.result);
                    } else if (result.status === 'error') {
                        clearInterval(pollInterval);
                        reject(new Error(result.error || 'An unknown error occurred during analysis.'));
                    }
                } catch (error) {
                    clearInterval(pollInterval);
                    reject(error);
                }
            }, 1000); // Poll every 1 second
        });
    }
}
