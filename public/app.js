// Main application logic

import { llm_models, llm_settings, llm_prompts } from './config.js';
import { PcapParser } from './pcapParser.js';
import { ReportRenderer } from './reportRenderer.js';

export class PCAPAnalyzerApp {
    constructor() {
        this.pcapParser = new PcapParser();
        this.reportRenderer = new ReportRenderer();
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
        this.exportPdf = document.getElementById('export-pdf');
        this.exportJson = document.getElementById('export-json');
        this.analysisProgress = document.getElementById('analysis-progress');
    }

    bindEvents() {
        this.messageClose.addEventListener('click', () => this.hideMessage());
        this.startAnalysisBtn.addEventListener('click', (e) => this.handleAnalysis(e));
        this.startComparisonBtn.addEventListener('click', (e) => this.handleComparison(e));
        this.exportPdf.addEventListener('click', () => this.exportPDF());
        this.exportJson.addEventListener('click', () => this.exportJSON());
    }

    populateLlmModels() {
        if (llm_models) {
            const models = Object.entries(llm_models).map(([key, value]) => ({
                key,
                name: value.name
            }));
            
            // Populate analysis model dropdown
            this.llmModelSelect1.innerHTML = '';
            models.forEach(model => {
                const option = document.createElement('option');
                option.value = model.key;
                option.textContent = model.name;
                this.llmModelSelect1.appendChild(option);
            });
            this.llmModelSelect1.value = llm_settings.default_llm_model_analysis;

            // Populate comparison model dropdown
            this.llmModelSelect2.innerHTML = '';
            models.forEach(model => {
                const option = document.createElement('option');
                option.value = model.key;
                option.textContent = model.name;
                this.llmModelSelect2.appendChild(option);
            });
            this.llmModelSelect2.value = llm_settings.default_llm_model_comparison;

        } else {
            console.error("No LLM models available in config.");
        }
    }

    showMessage(message, isError = true) {
        this.messageText.textContent = message;
        this.messageBox.classList.remove('hidden');
        this.messageBox.classList.add('fade-in');
        
        if (isError) {
            this.messageBox.querySelector('div').classList.remove('bg-green-100', 'border-green-500', 'text-green-700');
            this.messageBox.querySelector('div').classList.add('bg-red-100', 'border-red-500', 'text-red-700');
        } else {
            this.messageBox.querySelector('div').classList.remove('bg-red-100', 'border-red-500', 'text-red-700');
            this.messageBox.querySelector('div').classList.add('bg-green-100', 'border-green-500', 'text-green-700');
        }
    }

    hideMessage() {
        this.messageBox.classList.add('hidden');
        this.messageBox.classList.remove('fade-in');
    }

    updateProgress(percentage) {
        this.analysisProgress.style.width = `${percentage}%`;
    }

    async handleAnalysis(e) {
        e.preventDefault();
        
        // Clear previous report and show loading indicator
        this.reportContainer.innerHTML = '';
        this.loadingIndicator.classList.remove('hidden');
        this.exportButtons.classList.add('hidden');
        this.updateProgress(10);
        
        const file = this.pcapFile1.files[0];
        const llmModelKey = this.llmModelSelect1.value;

        if (!file) {
            this.showMessage('Please select a PCAP file for analysis.');
            this.loadingIndicator.classList.add('hidden');
            return;
        }

        try {
            this.updateProgress(30);
            
            // Parse PCAP file
            const parsedData = await this.pcapParser.parse(file, (progress) => {
                this.updateProgress(30 + (progress * 0.4));
            });
            
            this.updateProgress(70);
            
            // Simulate LLM analysis
            await new Promise(resolve => setTimeout(resolve, 1500));
            
            // Add mock analysis results
            parsedData.summary = "This network capture shows typical internet traffic with a mix of TCP and UDP protocols. Several HTTP requests were detected along with DNS queries. No significant security threats were identified.";
            
            // Add mock anomalies
            parsedData.anomalies = this.pcapParser.detectAnomalies(parsedData);
            
            this.updateProgress(100);
            
            // Store current analysis data
            this.currentAnalysisData = {
                type: 'analysis',
                data: parsedData,
                fileName: file.name
            };
            
            // Render report
            const report = this.reportRenderer.renderAnalysisReport(parsedData, file.name);
            this.reportContainer.innerHTML = report.html;
            report.postRender();
            
            // Show export buttons
            this.exportButtons.classList.remove('hidden');
            
        } catch (error) {
            this.showMessage(`An error occurred during analysis: ${error.message}`);
        } finally {
            this.loadingIndicator.classList.add('hidden');
        }
    }

    async handleComparison(e) {
        e.preventDefault();

        this.reportContainer.innerHTML = '';
        this.loadingIndicator.classList.remove('hidden');
        this.exportButtons.classList.add('hidden');
        this.updateProgress(10);
        
        const file1 = this.pcapFile2.files[0];
        const file2 = this.pcapFile3.files[0];
        const llmModelKey = this.llmModelSelect2.value;

        if (!file1 || !file2) {
            this.showMessage('Please select two PCAP files for comparison.');
            this.loadingIndicator.classList.add('hidden');
            return;
        }

        try {
            this.updateProgress(20);
            
            // Parse both PCAP files
            const parsedData1 = await this.pcapParser.parse(file1, (progress) => {
                this.updateProgress(20 + (progress * 0.2));
            });
            
            this.updateProgress(40);
            
            const parsedData2 = await this.pcapParser.parse(file2, (progress) => {
                this.updateProgress(40 + (progress * 0.2));
            });
            
            this.updateProgress(60);
            
            // Simulate LLM analysis
            await new Promise(resolve => setTimeout(resolve, 2000));
            
            // Create comparison data
            const comparisonData = {
                file1: parsedData1,
                file2: parsedData2,
                summary: "The two captures show similar network patterns but with differences in protocol distribution. File 1 has more HTTP traffic while File 2 shows higher UDP usage.",
                differences: [
                    "File 1 has 45% more TCP packets than File 2",
                    "File 2 contains RTP traffic not present in File 1",
                    "Different set of source IP addresses between files"
                ],
                similarities: [
                    "Both files have similar total packet counts",
                    "Same top destination IP addresses",
                    "Similar distribution of application protocols"
                ]
            };
            
            this.updateProgress(100);
            
            // Store current analysis data
            this.currentAnalysisData = {
                type: 'comparison',
                data: comparisonData,
                file1Name: file1.name,
                file2Name: file2.name
            };
            
            // Render report
            const report = this.reportRenderer.renderComparisonReport(comparisonData, file1.name, file2.name);
            this.reportContainer.innerHTML = report.html;
            report.postRender();
            
            // Show export buttons
            this.exportButtons.classList.remove('hidden');
            
        } catch (error) {
            this.showMessage(`An error occurred during comparison: ${error.message}`);
        } finally {
            this.loadingIndicator.classList.add('hidden');
        }
    }

    exportPDF() {
        this.showMessage('PDF export functionality would be implemented in a production version', false);
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
}

// Initialize the application when the DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.pcapAnalyzerApp = new PCAPAnalyzerApp();
});