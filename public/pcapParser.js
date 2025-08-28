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
        // This is a mock function to simulate parsing a PCAP file.
        // In a real application, you would use a library like 'pcap-parser' or 'wireshark' on a backend.
        return new Promise((resolve) => {
            let progress = 0;
            const interval = setInterval(() => {
                progress += 5;
                if (progressCallback) progressCallback(progress);
                if (progress >= 100) {
                    clearInterval(interval);
                    // Generate realistic-looking mock data
                    const packetCount = Math.floor(Math.random() * 5000) + 1000;
                    const duration = Math.floor(Math.random() * 60) + 10;
                    resolve({
                        packetCount: packetCount,
                        duration: duration,
                        protocolDistribution: this.mockProtocolDistribution(),
                        sip_rtp_info: this.mockSipRtpInfo(),
                        anomalies: this.detectAnomalies(),
                        timeline: this.mockTimeline(duration)
                    });
                }
            }, 50);
        });
    }

    mockProtocolDistribution() {
        // Generates mock protocol distribution data
        const protocols = ['tcp', 'udp', 'http', 'dns', 'ssl'];
        const distribution = {};
        let total = 0;
        protocols.forEach(p => {
            const count = Math.floor(Math.random() * 30) + 5;
            distribution[p] = count;
            total += count;
        });

        // Normalize to percentages
        const percentages = {};
        for (const p in distribution) {
            percentages[p] = (distribution[p] / total) * 100;
        }
        return percentages;
    }

    mockTimeline(duration) {
        // Generates mock timeline data for packets per second
        const timelineData = {};
        for (let i = 1; i <= duration; i++) {
            timelineData[i] = Math.floor(Math.random() * 50) + 1;
        }
        return timelineData;
    }

    mockSipRtpInfo() {
        // In a real implementation, this would extract SIP/RTP information
        // For demo purposes, return mock data
        return {
            sipCalls: Math.floor(Math.random() * 10),
            rtpStreams: Math.floor(Math.random() * 15),
            sipMethods: ['INVITE', 'ACK', 'BYE', 'CANCEL', 'OPTIONS', 'REGISTER', 'PRACK', 'SUBSCRIBE', 'NOTIFY', 'PUBLISH', 'INFO', 'REFER', 'MESSAGE', 'UPDATE'].slice(0, Math.floor(Math.random() * 4) + 1),
            codecs: ['G.711', 'iLBC', 'G.722'].slice(0, Math.floor(Math.random() * 3) + 1)
        };
    }

    detectAnomalies() {
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

        if (Math.random() > 0.8) {
            anomalies.push({
                time: "00:05:01.123",
                description: "Failed SSH login attempts from multiple IPs",
                severity: "High"
            });
        }

        return anomalies;
    }
}
