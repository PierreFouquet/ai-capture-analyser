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

    async readAsBase64(file) {
        return new Promise((resolve, reject) => {
            try {
                this.validateFile(file);
                const reader = new FileReader();
                reader.onload = () => {
                    // Extract the Base64 data from the result string
                    const base64Data = reader.result.split(',')[1];
                    resolve(base64Data);
                };
                reader.onerror = error => reject(error);
                reader.readAsDataURL(file);
            } catch (error) {
                reject(error);
            }
        });
    }
}
