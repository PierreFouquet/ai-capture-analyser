// This file handles all communication with the backend API
export class Backend {
    constructor() {
        this.sessionId = this.generateSessionId();
    }

    generateSessionId() {
        // Generate a unique session ID to keep track of analysis requests
        return 'session-' + Date.now() + '-' + Math.random().toString(36).substring(2, 9);
    }

    // Function to convert an ArrayBuffer to a Base64 string in chunks
    arrayBufferToBase64(buffer) {
        let binary = '';
        const bytes = new Uint8Array(buffer);
        const len = bytes.byteLength;
        for (let i = 0; i < len; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return window.btoa(binary);
    }

    async analyzePcap(file, llmModelKey) {
        // Read the file as an ArrayBuffer
        const arrayBuffer = await file.arrayBuffer();
        // Convert the ArrayBuffer to a Base64 string for transmission
        const base64PcapData = this.arrayBufferToBase64(arrayBuffer);

        try {
            // Use the single, unified API endpoint
            const response = await fetch('/api/analyze', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Session-ID': this.sessionId
                },
                body: JSON.stringify({
                    type: 'analysis',
                    pcap_data: base64PcapData,
                    file_name: file.name,
                    llm_model_key: llmModelKey,
                }),
            });

            const responseData = await response.json();
            
            if (!response.ok) {
                throw new Error(responseData.error || `Server responded with status ${response.status}`);
            }

            // Start polling the status endpoint to get the final result
            return this.pollStatus('/api/analyze/status');
        } catch (error) {
            console.error('API call failed:', error);
            throw new Error(`Analysis failed: ${error.message}`);
        }
    }

    async comparePcaps(file1, file2, llmModelKey) {
        const arrayBuffer1 = await file1.arrayBuffer();
        const base64PcapData1 = this.arrayBufferToBase64(arrayBuffer1);

        const arrayBuffer2 = await file2.arrayBuffer();
        const base64PcapData2 = this.arrayBufferToBase64(arrayBuffer2);
        
        try {
            // Use the single, unified API endpoint
            const response = await fetch('/api/analyze', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Session-ID': this.sessionId
                },
                body: JSON.stringify({
                    type: 'comparison',
                    pcap_data1: base64PcapData1,
                    file_name1: file1.name,
                    pcap_data2: base64PcapData2,
                    file_name2: file2.name,
                    llm_model_key: llmModelKey,
                }),
            });

            const responseData = await response.json();
            
            if (!response.ok) {
                throw new Error(responseData.error || `Server responded with status ${response.status}`);
            }

            // Start polling the status endpoint to get the final result
            return this.pollStatus('/api/analyze/status');
        } catch (error) {
            console.error('API call failed:', error);
            throw new Error(`Comparison failed: ${error.message}`);
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
                }
            }, 1000); // Poll every 1 second
        });
    }
}