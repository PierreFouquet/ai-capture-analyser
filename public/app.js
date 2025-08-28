// Main application logic
import { llm_models, llm_settings, llm_prompts } from './config.js';
import { PcapParser } from './pcapParser.js';
import { ReportRenderer } from './reportRenderer.js';
import { PDFExporter } from './pdfExporter.js';

export class PCAPAnalyzerApp {
    constructor() {
        // Initialize utilities
        this.pcapParser = new PcapParser();
        this.reportRenderer = new ReportRenderer();
        this.pdfExporter = new PDFExporter();

        // Hold the current report data
        this.currentAnalysisData = null;
        
        // Expose configuration for the entire application
        this.config = { llm_models, llm_settings, llm_prompts };
        
        // Initialize DOM elements and bind events
        this.initializeDOMElements();
        this.bindEvents();
        this.populateLlmModels();
    }

    /**
     * Initializes all necessary DOM elements.
     */
    initializeDOMElements() {
        this.pcapFile1 = document.getElementById('pcap-file-1');
        this.pcapFile2 = document.getElementById('pcap-file-2');
        this.pcapFile3 = document.getElementById('pcap-file-3');
        this.llmModelSelect1 = document.getElementById('model-select-1');
        this.llmModelSelect2 = document.getElementById('model-select-2');
        this.startAnalysisBtn = document.getElementById('start-analysis-btn');
        this.startComparisonBtn = document.getElementById('start-comparison-btn');
        this.reportContainer = document.getElementById('report-container');
        this.loadingIndicator = document.getElementById('loading-indicator');
        this.messageBox = document.getElementById('message-box');
        this.messageText = document.getElementById('message-text');
        this.messageClose = document.getElementById('message-close');
        this.exportPdfBtn = document.getElementById('export-pdf');
        this.exportJsonBtn = document.getElementById('export-json');
        this.exportButtonsContainer = document.getElementById('export-buttons');
        this.progressValue = document.getElementById('analysis-progress');
    }

    /**
     * Binds all event listeners to their respective DOM elements.
     */
    bindEvents() {
        this.startAnalysisBtn.addEventListener('click', () => this.startAnalysis());
        this.startComparisonBtn.addEventListener('click', () => this.startComparison());
        this.exportPdfBtn.addEventListener('click', () => this.exportPDF());
        this.exportJsonBtn.addEventListener('click', () => this.exportJSON());
        this.messageClose.addEventListener('click', () => this.hideMessage());
    }

    /**
     * Populates the LLM model dropdowns with available models from config.js.
     */
    populateLlmModels() {
        if (!this.config || !this.config.llm_models) {
            console.error("LLM models configuration is not available.");
            return;
        }

        const models = Object.entries(this.config.llm_models);
        [this.llmModelSelect1, this.llmModelSelect2].forEach(selectElement => {
            selectElement.innerHTML = '';
            models.forEach(([key, model]) => {
                const option = document.createElement('option');
                option.value = key;
                option.textContent = `${model.name} (${model.provider})`;
                selectElement.appendChild(option);
            });
        });
    }

    /**
     * Shows a custom message box with the given message.
     * @param {string} message The message to display.
     * @param {boolean} isError If true, the message is styled as an error.
     */
    showMessage(message, isError = false) {
        this.messageText.textContent = message;
        this.messageBox.style.display = 'flex';
        if (isError) {
            this.messageBox.classList.add('bg-red-200');
            this.messageText.classList.add('text-red-800');
            this.messageBox.classList.remove('bg-green-200');
            this.messageText.classList.remove('text-green-800');
        } else {
            this.messageBox.classList.add('bg-green-200');
            this.messageText.classList.add('text-green-800');
            this.messageBox.classList.remove('bg-red-200');
            this.messageText.classList.remove('text-red-800');
        }
    }

    /**
     * Hides the custom message box.
     */
    hideMessage() {
        this.messageBox.style.display = 'none';
    }

    /**
     * Starts the PCAP analysis process.
     */
    async startAnalysis() {
        const file = this.pcapFile1.files[0];
        const llmModelKey = this.llmModelSelect1.value;

        if (!file) {
            this.showMessage('Please select a PCAP file for analysis.', true);
            return;
        }

        this.hideMessage();
        this.loadingIndicator.style.display = 'flex';
        this.reportContainer.innerHTML = '';
        this.exportButtonsContainer.classList.add('hidden');

        try {
            // Simulate file parsing and LLM analysis
            const pcapData = await this.pcapParser.parse(file, (progress) => {
                this.progressValue.style.width = `${progress}%`;
            });
            
            const analysisPrompt = this.config.llm_prompts.analysis_pcap_explanation;
            const analysisSchema = this.config.llm_prompts.analysis_pcap_explanation_schema;

            // This part would typically send data to a backend for LLM analysis.
            // For this demo, we'll simulate the LLM response.
            const llmResponse = await new Promise(resolve => {
                setTimeout(() => {
                    resolve({
                        summary: "The packet capture primarily shows DNS and HTTP traffic, with a mix of TCP and UDP packets. A significant portion of the traffic is encrypted.",
                        anomalies_and_errors: ["Possible DNS tunneling detected due to unusual query patterns.", "Several TCP retransmission events observed."],
                        sip_rtp_info: "No SIP or RTP traffic was identified in this capture.",
                        important_timestamps_packets: "The high number of TCP retransmissions began around packet 1500.",
                    });
                }, 1500); // Simulate network latency and processing time
            });
            
            const fullAnalysisData = {
                ...pcapData,
                llmAnalysis: llmResponse
            };

            this.currentAnalysisData = {
                type: 'analysis',
                data: fullAnalysisData,
                fileName: file.name
            };

            const report = this.reportRenderer.renderAnalysisReport(fullAnalysisData, file.name);
            this.reportContainer.innerHTML = report.html;
            report.postRender();

            this.showMessage('Analysis complete!', false);
            this.exportButtonsContainer.classList.remove('hidden');

        } catch (error) {
            console.error('Analysis failed:', error);
            this.showMessage(`Analysis failed: ${error.message}`, true);
        } finally {
            this.loadingIndicator.style.display = 'none';
            this.progressValue.style.width = '0%';
        }
    }

    /**
     * Starts the PCAP comparison process.
     */
    async startComparison() {
        const file1 = this.pcapFile2.files[0];
        const file2 = this.pcapFile3.files[0];
        const llmModelKey = this.llmModelSelect2.value;
        
        if (!file1 || !file2) {
            this.showMessage('Please select two PCAP files for comparison.', true);
            return;
        }

        this.hideMessage();
        this.loadingIndicator.style.display = 'flex';
        this.reportContainer.innerHTML = '';
        this.exportButtonsContainer.classList.add('hidden');

        try {
            // Simulate parsing of both files
            const pcapData1 = await this.pcapParser.parse(file1, (progress) => {
                this.progressValue.style.width = `${progress / 2}%`;
            });
            const pcapData2 = await this.pcapParser.parse(file2, (progress) => {
                this.progressValue.style.width = `${50 + progress / 2}%`;
            });

            // This part would typically send data to a backend for LLM comparison.
            // For this demo, we'll simulate the LLM response.
            const llmResponse = await new Promise(resolve => {
                setTimeout(() => {
                    resolve({
                        overall_comparison_summary: "The two packet captures show significant differences. File 1 contains a high volume of web traffic, while File 2 is dominated by VoIP (SIP and RTP) communication.",
                        key_differences: ["File 1 shows extensive HTTP and DNS activity; File 2 has none.", "File 2 contains SIP call signaling and multiple RTP streams for voice data, which are completely absent in File 1.", "File 1 contains a variety of protocols, while File 2 is highly specialized."],
                        key_similarities: ["Both captures were of a similar duration.", "Both captures were from the same network segment."],
                        security_implications: ["The high volume of DNS and HTTP traffic in File 1 could indicate a potential botnet or malware activity if not properly controlled.", "The unencrypted RTP streams in File 2 could be vulnerable to eavesdropping."],
                        important_timestamps_packets: "In File 2, the SIP INVITE for the call occurred at packet 23 and the call ended with a BYE at packet 350.",
                    });
                }, 2000); // Simulate network latency and processing time
            });

            const fullComparisonData = {
                file1: pcapData1,
                file2: pcapData2,
                llmComparison: llmResponse
            };

            this.currentAnalysisData = {
                type: 'comparison',
                data: fullComparisonData,
                file1Name: file1.name,
                file2Name: file2.name
            };

            const report = this.reportRenderer.renderComparisonReport(fullComparisonData, file1.name, file2.name);
            this.reportContainer.innerHTML = report.html;
            report.postRender();

            this.showMessage('Comparison complete!', false);
            this.exportButtonsContainer.classList.remove('hidden');

        } catch (error) {
            console.error('Comparison failed:', error);
            this.showMessage(`Comparison failed: ${error.message}`, true);
        } finally {
            this.loadingIndicator.style.display = 'none';
            this.progressValue.style.width = '0%';
        }
    }

    /**
     * Exports the current report as a PDF.
     */
    exportPDF() {
        if (!this.currentAnalysisData) return;
        
        try {
            if (this.currentAnalysisData.type === 'analysis') {
                this.pdfExporter.exportAnalysisReport(
                    this.currentAnalysisData.data.llmAnalysis, 
                    this.currentAnalysisData.fileName
                );
            } else {
                this.pdfExporter.exportComparisonReport(
                    this.currentAnalysisData.data.llmComparison,
                    this.currentAnalysisData.file1Name,
                    this.currentAnalysisData.file2Name
                );
            }
            
            setTimeout(() => {
                this.hideMessage();
                this.showMessage('PDF downloaded successfully!', false);
            }, 1000);
            
        } catch (error) {
            console.error('Error generating PDF:', error);
            this.showMessage('Failed to generate PDF. Please try again.', true);
        }
    }

    /**
     * Exports the current report as a JSON file.
     */
    exportJSON() {
        if (!this.currentAnalysisData) return;
        
        const dataStr = JSON.stringify(this.currentAnalysisData, null, 2);
        const dataUri = 'data:application/json;charset=utf-8,'+ encodeURIComponent(dataStr);
        
        const exportFileDefaultName = `pcap-analysis-${Date.now()}.json`;
        
        const linkElement = document.createElement('a');
        linkElement.setAttribute('href', dataUri);
        linkElement.setAttribute('download', exportFileDefaultName);
        linkElement.click();
        
        this.showMessage('JSON report downloaded successfully', false);
    }
}

// Initialize the application when the DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.pcapAnalyzerApp = new PCAPAnalyzerApp();
});
