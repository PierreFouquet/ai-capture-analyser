// Main application logic
import { llm_models, llm_settings } from './config.js';
import { PcapParser } from './pcapParser.js';
import { ReportRenderer } from './reportRenderer.js';
import { PDFExporter } from './pdfExporter.js';

export class PCAPAnalyzerApp {
    constructor() {
        this.pcapParser = new PcapParser();
        this.reportRenderer = new ReportRenderer();
        this.pdfExporter = new PDFExporter();
        this.currentAnalysisData = null;
        
        this.initializeDOMElements();
        this.bindEvents();
        this.populateLlmModels();
    }

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

        this.comparisonMode = false;
    }

    bindEvents() {
        this.startAnalysisBtn.addEventListener('click', () => this.startAnalysis());
        this.startComparisonBtn.addEventListener('click', () => this.startComparison());
        
        // Event listener for export buttons
        document.getElementById('export-pdf').addEventListener('click', () => this.exportPDF());
        document.getElementById('export-json').addEventListener('click', () => this.exportJSON());

        // Event listener for tab selection
        const tabButtons = document.querySelectorAll('.tab-button');
        tabButtons.forEach(button => {
            button.addEventListener('click', (event) => {
                const targetTab = event.target.getAttribute('data-tab');
                this.switchTab(targetTab);
            });
        });

        // Hide message box on close
        this.messageClose.addEventListener('click', () => this.hideMessage());
    }

    switchTab(targetTab) {
        // Remove 'active' class from all tab buttons
        const tabButtons = document.querySelectorAll('.tab-button');
        tabButtons.forEach(button => {
            button.classList.remove('bg-blue-600', 'text-white');
            button.classList.add('bg-gray-200', 'text-gray-800');
        });

        // Add 'active' class to the clicked tab button
        document.querySelector(`[data-tab="${targetTab}"]`).classList.remove('bg-gray-200', 'text-gray-800');
        document.querySelector(`[data-tab="${targetTab}"]`).classList.add('bg-blue-600', 'text-white');

        // Hide all tab contents
        const tabContents = document.querySelectorAll('.tab-content');
        tabContents.forEach(content => {
            content.classList.add('hidden');
        });

        // Show the target tab content
        document.getElementById(targetTab).classList.remove('hidden');

        // Toggle file inputs and buttons based on tab
        const analysisInputs = document.getElementById('analysis-inputs');
        const comparisonInputs = document.getElementById('comparison-inputs');

        if (targetTab === 'analyze-tab') {
            analysisInputs.classList.remove('hidden');
            comparisonInputs.classList.add('hidden');
            this.comparisonMode = false;
        } else if (targetTab === 'compare-tab') {
            analysisInputs.classList.add('hidden');
            comparisonInputs.classList.remove('hidden');
            this.comparisonMode = true;
        }
    }

    populateLlmModels() {
        if (!llm_models) return;
        
        const models = Object.keys(llm_models);
        this.llmModelSelect1.innerHTML = models.map(key => `<option value="${key}">${llm_models[key].name}</option>`).join('');
        this.llmModelSelect2.innerHTML = models.map(key => `<option value="${key}">${llm_models[key].name}</option>`).join('');
    }

    showMessage(message, isError = false) {
        this.messageText.textContent = message;
        this.messageBox.style.display = 'flex';
        if (isError) {
            this.messageBox.classList.remove('bg-green-500');
            this.messageBox.classList.add('bg-red-500');
        } else {
            this.messageBox.classList.remove('bg-red-500');
            this.messageBox.classList.add('bg-green-500');
        }
    }

    hideMessage() {
        this.messageBox.style.display = 'none';
    }

    async startAnalysis() {
        const file = this.pcapFile3.files[0];
        const llmModelKey = this.llmModelSelect2.value;
        this.hideMessage();
        this.reportContainer.innerHTML = '';
        this.exportButtons.classList.add('hidden');

        if (!file) {
            this.showMessage('Please select a PCAP file to analyze.', true);
            return;
        }

        this.showLoadingIndicator();
        this.updateProgress(10);

        try {
            const analysisData = await this.pcapParser.parse(file, (progress) => this.updateProgress(progress));
            this.updateProgress(80);

            // Fetch the LLM-generated report
            const llmReport = await this.fetchLlmReport('analysis', analysisData, llmModelKey);
            this.updateProgress(90);

            // Ensure llmReport has a protocolDistribution, even if empty
            if (!llmReport.protocolDistribution) {
                llmReport.protocolDistribution = analysisData.protocolDistribution || {};
            }

            const reportResult = this.reportRenderer.renderAnalysisReport(llmReport, file.name);
            this.currentAnalysisData = {
                type: 'analysis',
                data: llmReport,
                fileName: file.name
            };
            this.updateProgress(100);

            this.reportContainer.innerHTML = reportResult.html;
            if (reportResult.postRender) {
                reportResult.postRender();
            }

            this.exportButtons.classList.remove('hidden');
            this.hideLoadingIndicator();
            this.showMessage('Analysis complete!', false);

        } catch (error) {
            console.error(error);
            this.hideLoadingIndicator();
            this.showMessage(`Error during analysis: ${error.message}`, true);
        }
    }

    async startComparison() {
        const file1 = this.pcapFile1.files[0];
        const file2 = this.pcapFile2.files[0];
        const llmModelKey = this.llmModelSelect1.value;
        this.hideMessage();
        this.reportContainer.innerHTML = '';
        this.exportButtons.classList.add('hidden');

        if (!file1 || !file2) {
            this.showMessage('Please select two PCAP files for comparison.', true);
            return;
        }

        this.showLoadingIndicator();
        this.updateProgress(10);

        try {
            const data1 = await this.pcapParser.parse(file1, (progress) => this.updateProgress(progress / 2));
            this.updateProgress(50);
            const data2 = await this.pcapParser.parse(file2, (progress) => this.updateProgress(50 + progress / 2));
            this.updateProgress(80);

            const comparisonReport = await this.fetchLlmReport('comparison', { data1, data2 }, llmModelKey);
            this.updateProgress(90);

            const reportResult = this.reportRenderer.renderComparisonReport(comparisonReport, file1.name, file2.name);
            this.currentAnalysisData = {
                type: 'comparison',
                data: comparisonReport,
                file1Name: file1.name,
                file2Name: file2.name
            };
            this.updateProgress(100);

            this.reportContainer.innerHTML = reportResult.html;
            if (reportResult.postRender) {
                reportResult.postRender();
            }

            this.exportButtons.classList.remove('hidden');
            this.hideLoadingIndicator();
            this.showMessage('Comparison complete!', false);

        } catch (error) {
            console.error(error);
            this.hideLoadingIndicator();
            this.showMessage(`Error during comparison: ${error.message}`, true);
        }
    }

    async fetchLlmReport(reportType, pcapData, llmModelKey) {
        const payload = {
            report_type: reportType,
            pcap_data: pcapData,
            llm_model_key: llmModelKey,
        };

        const response = await fetch('/api/analyze', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                // This simulates a session ID for Durable Objects
                'X-Session-ID': 'pcap-analysis-session-' + Date.now()
            },
            body: JSON.stringify(payload),
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || "An error occurred during LLM analysis.");
        }

        // We poll the status from the Durable Object
        const result = await this.pollDurableObjectStatus(response.headers.get('Location'));
        return result.result;
    }

    async pollDurableObjectStatus(statusUrl) {
        return new Promise((resolve, reject) => {
            const interval = setInterval(async () => {
                try {
                    const response = await fetch(statusUrl);
                    if (!response.ok) {
                        clearInterval(interval);
                        const error = await response.json();
                        return reject(new Error(error.error || 'Failed to poll status.'));
                    }

                    const status = await response.json();
                    if (status.status === 'complete') {
                        clearInterval(interval);
                        resolve(status);
                    } else if (status.status === 'error') {
                        clearInterval(interval);
                        reject(new Error(status.result.error || 'Analysis failed.'));
                    }
                    // Continue polling if status is 'processing'
                } catch (error) {
                    clearInterval(interval);
                    reject(error);
                }
            }, 1000); // Poll every 1 second
        });
    }

    showLoadingIndicator() {
        this.loadingIndicator.classList.remove('hidden');
    }

    hideLoadingIndicator() {
        this.loadingIndicator.classList.add('hidden');
    }

    updateProgress(percentage) {
        const progressBar = document.getElementById('analysis-progress');
        progressBar.style.width = `${percentage}%`;
    }

    exportPDF() {
        if (!this.currentAnalysisData) return;
        
        this.showMessage('Generating PDF...', false);
        
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
} // Added missing closing brace for the class

// Initialize the application when the DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.pcapAnalyzerApp = new PCAPAnalyzerApp();
});
