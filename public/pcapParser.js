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
                    resolve(this.generateMockReport(file));
                }
            }, 50); // Speed up the progress bar for better UX
        });
    }

    generateMockReport(file) {
        // Generate a random-looking report based on the file name and size
        const fileName = file.name.toLowerCase();
        const fileSizeKB = file.size / 1024;

        let protocolDistribution = {};
        let summary = "This is a basic analysis of the network traffic captured in this file.";
        let anomalies = [];
        let sipRtpInfo = "N/A";
        let timestamps = "N/A";

        // Heuristic-based mock data generation
        if (fileName.includes('voip') || fileName.includes('voice') || fileName.includes('call')) {
            protocolDistribution = {
                'SIP': 30,
                'RTP': 50,
                'TCP': 10,
                'UDP': 5,
                'DNS': 5
            };
            summary = "This capture appears to be from a VoIP call, dominated by SIP and RTP traffic.";
            anomalies.push({
                time: "00:01:23",
                description: "High volume of jitter on an RTP stream.",
                severity: "Medium"
            });
            sipRtpInfo = "Detected 1 SIP call with 2 RTP streams. Codec: G.711u.";
            timestamps = "00:00:15 - SIP INVITE, 00:00:18 - RTP stream starts.";
        } else if (fileName.includes('web') || fileName.includes('http') || fileName.includes('browsing')) {
            protocolDistribution = {
                'HTTP': 35,
                'HTTPS': 45,
                'DNS': 10,
                'TCP': 8,
                'UDP': 2
            };
            summary = "This file contains a typical web browsing session, with a mix of secure (HTTPS) and unsecure (HTTP) traffic.";
            anomalies.push({
                time: "00:00:45",
                description: "Multiple redirects detected on a single HTTP session.",
                severity: "Low"
            });
        } else if (fileName.includes('dns') || fileName.includes('scan')) {
            protocolDistribution = {
                'DNS': 70,
                'UDP': 20,
                'TCP': 10
            };
            summary = "This capture shows a high number of DNS queries, suggesting a potential network scan or unusual activity.";
            anomalies.push({
                time: "00:00:10",
                description: "Over 100 DNS queries in a 5-second interval.",
                severity: "High"
            });
            timestamps = "Packets 10-110 contain a DNS flood.";
        } else {
            // Default random-ish data for generic files
            protocolDistribution = {
                'TCP': Math.floor(Math.random() * 40) + 10,
                'UDP': Math.floor(Math.random() * 20) + 5,
                'DNS': Math.floor(Math.random() * 15) + 5,
                'HTTP': Math.floor(Math.random() * 10) + 5,
                'HTTPS': Math.floor(Math.random() * 10) + 5,
                'ICMP': Math.floor(Math.random() * 5) + 1
            };
            const total = Object.values(protocolDistribution).reduce((sum, val) => sum + val, 0);
            for (const key in protocolDistribution) {
                protocolDistribution[key] = Math.round((protocolDistribution[key] / total) * 100);
            }
        }
        
        return {
            packetCount: Math.floor(fileSizeKB * (Math.random() * 5 + 10)), // A rough simulation
            duration: Math.floor(fileSizeKB / 10) + 1,
            protocolDistribution: protocolDistribution,
            sipRtpInfo: sipRtpInfo,
            anomalies: anomalies,
            summary: summary,
            timeline: this.generateMockTimeline(),
            important_timestamps_packets: timestamps,
            // Mock data for LLM
            llmAnalysis: {
                overall_comparison_summary: "N/A",
                key_differences: [],
                key_similarities: [],
                security_implications: [],
                important_timestamps_packets: "N/A"
            }
        };
    }

    generateMockTimeline() {
        const labels = Array.from({length: 20}, (_, i) => `${i * 5}s`);
        const values = Array.from({length: 20}, () => Math.floor(Math.random() * 50));
        return { labels, values };
    }

    detectAnomalies(pcapData) {
        // This is where a real-world anomaly detection would go.
        // For now, it's mocked in generateMockReport.
        return [];
    }
}
