// PCAP parsing utilities

export class PcapParser {
    constructor() {
        this.supportedFormats = ['.pcap', '.pcapng'];
        this.maxFileSize = 10 * 1024 * 1024; // 10MB
    }

    validateFile(file) {
        // Check file type
        const isValidFormat = this.supportedFormats.some(format => 
            file.name.toLowerCase().endsWith(format)
        );
        
        if (!isValidFormat) {
            throw new Error(`Unsupported file format. Please use ${this.supportedFormats.join(' or ')} files.`);
        }
        
        // Check file size
        if (file.size > this.maxFileSize) {
            throw new Error(`File size exceeds the maximum limit of ${this.maxFileSize / 1024 / 1024}MB.`);
        }
        
        return true;
    }

    async parse(file, progressCallback = null) {
        try {
            this.validateFile(file);
            
            // In a real implementation, this would parse the actual PCAP file
            // For this demo, we'll simulate parsing with a mock implementation
            return await this.mockParse(file, progressCallback);
        } catch (error) {
            console.error('PCAP parsing error:', error);
            throw error;
        }
    }

    async mockParse(file, progressCallback) {
        return new Promise((resolve) => {
            let progress = 0;
            const interval = setInterval(() => {
                progress += 5;
                if (progressCallback) progressCallback(progress);
                
                if (progress >= 100) {
                    clearInterval(interval);
                    
                    // Generate mock parsing results
                    const packetCount = Math.floor(Math.random() * 1000) + 500;
                    const protocols = ['TCP', 'UDP', 'HTTP', 'DNS', 'TLS'];
                    const protocolDistribution = {};
                    
                    protocols.forEach(protocol => {
                        protocolDistribution[protocol] = Math.floor(Math.random() * 100);
                    });
                    
                    // Normalize to 100%
                    const total = Object.values(protocolDistribution).reduce((a, b) => a + b, 0);
                    for (const protocol in protocolDistribution) {
                        protocolDistribution[protocol] = Math.round((protocolDistribution[protocol] / total) * 100);
                    }
                    
                    const result = {
                        packetCount,
                        protocolDistribution,
                        duration: (Math.random() * 10 + 1).toFixed(2),
                        startTime: new Date(Date.now() - Math.random() * 86400000).toISOString(),
                        endTime: new Date().toISOString(),
                        sourceIPs: Array.from({length: 5}, () => 
                            `192.168.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`
                        ),
                        destinationIPs: Array.from({length: 5}, () => 
                            `10.0.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`
                        ),
                        topConversations: Array.from({length: 5}, () => ({
                            source: `192.168.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}:${Math.floor(Math.random() * 65535)}`,
                            destination: `10.0.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}:${Math.floor(Math.random() * 65535)}`,
                            packets: Math.floor(Math.random() * 100) + 10,
                            bytes: Math.floor(Math.random() * 10000) + 1000
                        }))
                    };
                    
                    resolve(result);
                }
            }, 100);
        });
    }

    extractSipRtpInfo(pcapData) {
        // In a real implementation, this would extract SIP/RTP information
        // For demo purposes, return mock data
        return {
            sipCalls: Math.floor(Math.random() * 10),
            rtpStreams: Math.floor(Math.random() * 15),
            sipMethods: ['INVITE', 'ACK', 'BYE', 'CANCEL'].slice(0, Math.floor(Math.random() * 4) + 1),
            codecs: ['G.711a', 'G.711u', 'iLBC', 'G.722'].slice(0, Math.floor(Math.random() * 3) + 1)
        };
    }

    detectAnomalies(pcapData) {
        // In a real implementation, this would detect network anomalies
        // For demo purposes, return mock anomalies
        const anomalies = [];
        
        if (Math.random() > 0.3) {
            anomalies.push({
                time: "00:01:23.456",
                description: "Multiple DNS queries to unknown domains",
                severity: "Medium"
            });
        }
        
        if (Math.random() > 0.5) {
            anomalies.push({
                time: "00:02:15.789",
                description: "Unusual TCP retransmission pattern detected",
                severity: "Low"
            });
        }
        
        if (Math.random() > 0.7) {
            anomalies.push({
                time: "00:03:47.123",
                description: "Possible port scanning activity detected",
                severity: "High"
            });
        }
        
        return anomalies;
    }
}