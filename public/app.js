// Main application logic
import { llm_models, llm_settings, llm_prompts } from './config.js';
import { PcapParser } from './pcapParser.js';
import { ReportRenderer } from './reportRenderer.js';
import { PDFExporter } from './pdfExporter.js';

export class PCAPAnalyzerApp {
    constructor() {
        // Instantiate utility classes
        this.pcapParser = new PcapParser();
        this.reportRenderer = new ReportRenderer();
        this.pdfExporter = new PDFExporter();

        // State to hold the current analysis data
        this.currentAnalysisData = null;

        // Initialize DOM elements and bind event listeners
        this.initializeDOMElements();
        this.bindEvents();
        this.populateLlmModels();
    }

    // Finds and stores references to key HTML elements
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
        this.exportButtons = document.getElementById('export-buttons');
        this.exportPdfBtn = document.getElementById('export-pdf');
        this.exportJsonBtn = document.getElementById('export-json');
    }

    // Attaches event listeners to interactive elements
    bindEvents() {
        this.startAnalysisBtn.addEventListener('click', () => this.startAnalysis());
        this.startComparisonBtn.addEventListener('click', () => this.startComparison());
        this.messageClose.addEventListener('click', () => this.hideMessage());
        this.exportPdfBtn.addEventListener('click', () => this.exportPDF());
        this.exportJsonBtn.addEventListener('click', () => this.exportJSON());
    }

    // Populates the LLM model dropdowns from the imported config
    populateLlmModels() {
        const models = Object.keys(llm_models);
        const createOptions = (selectElement) => {
            selectElement.innerHTML = ''; // Clear existing options
            models.forEach(key => {
                const option = document.createElement('option');
                option.value = key;
                option.textContent = llm_models[key].name;
                selectElement.appendChild(option);
            });
        };
        createOptions(this.llmModelSelect1);
        createOptions(this.llmModelSelect2);

        // Set default values if available
        this.llmModelSelect1.value = llm_settings.default_llm_model_analysis || models[0];
        this.llmModelSelect2.value = llm_settings.default_llm_model_comparison || models[0];
    }

    // Shows a message in a custom message box
    showMessage(message, isError = false) {
        this.messageText.textContent = message;
        this.messageBox.style.display = 'flex';
        this.messageBox.classList.remove('bg-red-500', 'bg-green-500');
        if (isError) {
            this.messageBox.classList.add('bg-red-500');
        } else {
            this.messageBox.classList.add('bg-green-500');
        }
    }

    // Hides the custom message box
    hideMessage() {
        this.messageBox.style.display = 'none';
    }

    // Handles the analysis button click
    async startAnalysis() {
        const file = this.pcapFile1.files[0];
        const llmModelKey = this.llmModelSelect1.value;

        if (!file) {
            this.showMessage('Please select a PCAP file for analysis.', true);
            return;
        }

        this.loadingIndicator.style.display = 'flex';
        this.reportContainer.innerHTML = '';
        this.exportButtons.classList.add('hidden');
        this.hideMessage();

        try {
            // Simulate parsing the file and getting a JSON report
            const pcapData = await this.pcapParser.parse(file, (progress) => {
                const progressBar = document.getElementById('analysis-progress');
                if (progressBar) {
                    progressBar.style.width = `${progress}%`;
                }
            });

            // Mocking the LLM API call response structure from the backend
            const analysisResult = {
                summary: "This report analyzes a sample PCAP file. It contains a mix of network traffic, primarily focusing on TCP and HTTP protocols. There are several DNS queries, some of which appear to be for external services. No major anomalies or security threats were detected in this small sample.",
                anomalies_and_errors: [
                    "Repeated DNS queries for a single domain.",
                    "A few out-of-order TCP packets."
                ],
                sip_rtp_info: "No SIP or RTP traffic was identified in this capture.",
                important_timestamps_packets: "Packet 10 and 15 show the start of a TCP handshake.",
                protocol_distribution: pcapData.protocolDistribution, // Use data from the parser
                packetCount: pcapData.packetCount,
                duration: pcapData.duration,
                timeline: pcapData.timeline
            };

            this.currentAnalysisData = {
                type: 'analysis',
                data: analysisResult,
                fileName: file.name
            };

            const renderedReport = this.reportRenderer.renderAnalysisReport(analysisResult, file.name);
            this.reportContainer.innerHTML = renderedReport.html;
            renderedReport.postRender();

            this.showMessage('Analysis complete!', false);
            this.loadingIndicator.style.display = 'none';
            this.exportButtons.classList.remove('hidden');

        } catch (error) {
            console.error('Analysis failed:', error);
            this.showMessage(`Analysis failed: ${error.message}`, true);
            this.loadingIndicator.style.display = 'none';
            this.exportButtons.classList.add('hidden');
        }
    }

    // Handles the comparison button click
    async startComparison() {
        const file1 = this.pcapFile2.files[0];
        const file2 = this.pcapFile3.files[0];
        const llmModelKey = this.llmModelSelect2.value;

        if (!file1 || !file2) {
            this.showMessage('Please select two PCAP files for comparison.', true);
            return;
        }

        this.loadingIndicator.style.display = 'flex';
        this.reportContainer.innerHTML = '';
        this.exportButtons.classList.add('hidden');
        this.hideMessage();

        try {
            // Mock file parsing
            const pcapData1 = await this.pcapParser.parse(file1, (progress) => {
                const progressBar = document.getElementById('analysis-progress');
                if (progressBar) progressBar.style.width = `${progress / 2}%`; // Half progress
            });
            const pcapData2 = await this.pcapParser.parse(file2, (progress) => {
                const progressBar = document.getElementById('analysis-progress');
                if (progressBar) progressBar.style.width = `${50 + progress / 2}%`; // Remaining progress
            });

            // Dynamically mock the comparison report based on file names for a better demo experience
            let comparisonResult;
            if (file1.name === file2.name) {
                // Scenario 1: Same file uploaded twice
                comparisonResult = {
                    overall_comparison_summary: "These two captures appear to be identical. No significant differences in protocol distribution, packet count, or traffic patterns were detected.",
                    key_differences: [],
                    key_similarities: [
                        "Identical protocol distributions.",
                        "Identical packet counts and traffic volume.",
                        "Identical timestamp and flow information."
                    ],
                    security_implications: "No security implications found as the files are identical.",
                    important_timestamps_packets: "N/A",
                    file1: pcapData1,
                    file2: pcapData2
                };
            } else {
                // Scenario 2: Different files, return the default mock comparison
                comparisonResult = {
                    overall_comparison_summary: "File 1 is a typical web browsing capture with a mix of HTTP and HTTPS traffic, while File 2 appears to contain mostly voice-over-IP (VoIP) traffic, with a high concentration of SIP and RTP packets. This suggests File 1 is from a regular internet user and File 2 is from a communication system.",
                    key_differences: [
                        "Protocol distribution: File 1 is dominated by HTTP/HTTPS, while File 2 is dominated by SIP/RTP.",
                        "File 2 has a higher volume of UDP traffic due to RTP, whereas File 1 is primarily TCP.",
                        "The average packet size in File 2 is smaller due to the nature of VoIP payloads."
                    ],
                    key_similarities: [
                        "Both captures contain some background DNS and ARP traffic.",
                        "Both show evidence of standard TCP handshakes at the beginning of sessions."
                    ],
                    security_implications: "The VoIP traffic in File 2, if unencrypted (G.711u), is vulnerable to eavesdropping. File 1 contains standard web traffic, with the usual security considerations for unencrypted HTTP connections.",
                    important_timestamps_packets: "In File 2, packet 42 and 43 mark the start of a SIP INVITE transaction.",
                    file1: pcapData1,
                    file2: pcapData2
                };
            }

            this.currentAnalysisData = {
                type: 'comparison',
                data: comparisonResult,
                file1Name: file1.name,
                file2Name: file2.name
            };

            const renderedReport = this.reportRenderer.renderComparisonReport(comparisonResult, file1.name, file2.name);
            this.reportContainer.innerHTML = renderedReport.html;
            renderedReport.postRender();

            this.showMessage('Comparison complete!', false);
            this.loadingIndicator.style.display = 'none';
            this.exportButtons.classList.remove('hidden');

        } catch (error) {
            console.error('Comparison failed:', error);
            this.showMessage(`Comparison failed: ${error.message}`, true);
            this.loadingIndicator.style.display = 'none';
            this.exportButtons.classList.add('hidden');
        }
    }

    // Exports the current report as a PDF
    exportPDF() {
        if (!this.currentAnalysisData) return;

        try {
            if (this.currentAnalysisData.type === 'analysis') {
                this.pdfExporter.exportAnalysisReport(
                    this.currentAnalysisData.data,
                    this.currentAnalysisData.fileName
                );
            } else {
                this.pdfExporter.exportComparisonReport(
                    this.currentAnalysisData.data,
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

    // Exports the current report as a JSON file
    exportJSON() {
        if (!this.currentAnalysisData) return;

        const dataStr = JSON.stringify(this.currentAnalysisData, null, 2);
        const dataUri = 'data:application/json;charset=utf-8,' + encodeURIComponent(dataStr);

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
