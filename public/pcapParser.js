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
                    resolve(this.generateMockPcapData());
                }
            }, 50);
        });
    }

    generateMockPcapData() {
        const protocolDistribution = {
            'TCP': Math.floor(Math.random() * 50) + 10,
            'UDP': Math.floor(Math.random() * 30) + 5,
            'HTTP': Math.floor(Math.random() * 20) + 1,
            'HTTPS': Math.floor(Math.random() * 15) + 1,
            'DNS': Math.floor(Math.random() * 10) + 1
        };
        const totalPackets = Object.values(protocolDistribution).reduce((sum, count) => sum + count, 0);

        // Generate mock timeline data
        const timelineData = Array.from({length: 20}, () => Math.floor(Math.random() * 100));
        
        return {
            packetCount: totalPackets,
            duration: 10, // Mock duration in seconds
            protocolDistribution,
            timeline: {
                labels: Array.from({length: 20}, (_, i) => `${i + 1}s`),
                data: timelineData
            }
        };
    }
}
