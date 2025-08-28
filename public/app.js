// Main application logic
import { PcapParser } from './pcapParser.js';
import { ReportRenderer } from './reportRenderer.js';
import { PDFExporter } from './pdfExporter.js';
import { Backend } from './backend.js';

export class PCAPAnalyzerApp {
    constructor() {
        this.pcapParser = new PcapParser();
        this.reportRenderer = new ReportRenderer();
        this.pdfExporter = new PDFExporter();
        this.backend = new Backend();
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
        this.exportPdfBtn = document.getElementById('export-pdf');
        this.exportJsonBtn = document.getElementById('export-json');
    }

    bindEvents() {
        this.startAnalysisBtn.addEventListener('click', () => this.startAnalysis());
        this.startComparisonBtn.addEventListener('click', () => this.startComparison());
        this.exportPdfBtn.addEventListener('click', () => this.exportPDF());
        this.exportJsonBtn.addEventListener('click', () => this.exportJSON());
        this.messageClose.addEventListener('click', () => this.hideMessage());
    }
    
    populateLlmModels() {
        // Assume this is imported correctly from config.js
        const { llm_models } = window.pcapAnalyzerConfig; 
        const select1 = this.llmModelSelect1;
        const select2 = this.llmModelSelect2;

        for (const key in llm_models) {
            if (llm_models.hasOwnProperty(key)) {
                const option1 = document.createElement('option');
                option1.value = key;
                option1.textContent = llm_models[key].name;
                select1.appendChild(option1);

                const option2 = document.createElement('option');
                option2.value = key;
                option2.textContent = llm_models[key].name;
                select2.appendChild(option2);
            }
        }
    }

    async startAnalysis() {
        const file = this.pcapFile1.files[0] || this.pcapFile3.files[0];
        const llmModelKey = this.llmModelSelect1.value;

        if (!file) {
            this.showMessage('Please select a PCAP file to analyze.');
            return;
        }

        this.showLoading('Analyzing PCAP data. This may take a moment...');
        this.hideReport();

        try {
            const result = await this.backend.analyzePcap(file, llmModelKey);
            this.currentAnalysisData = {
                type: 'analysis',
                data: result,
                fileName: file.name
            };
            this.renderReport(this.currentAnalysisData);
        } catch (error) {
            console.error('Analysis failed:', error);
            this.showMessage(`Analysis failed: ${error.message || 'An unknown error occurred during analysis.'}`, true);
        } finally {
            this.hideLoading();
        }
    }

    async startComparison() {
        const file1 = this.pcapFile1.files[0];
        const file2 = this.pcapFile2.files[0];
        const llmModelKey = this.llmModelSelect2.value;

        if (!file1 || !file2) {
            this.showMessage('Please select two PCAP files for comparison.');
            return;
        }

        this.showLoading('Comparing PCAP data. This may take a moment...');
        this.hideReport();

        try {
            const result = await this.backend.comparePcaps(file1, file2, llmModelKey);
            this.currentAnalysisData = {
                type: 'comparison',
                data: result,
                file1Name: file1.name,
                file2Name: file2.name
            };
            this.renderReport(this.currentAnalysisData);
        } catch (error) {
            console.error('Comparison failed:', error);
            this.showMessage(`Comparison failed: ${error.message || 'An unknown error occurred during analysis.'}`, true);
        } finally {
            this.hideLoading();
        }
    }
    
    renderReport(analysisData) {
        if (analysisData.type === 'analysis') {
            const renderResult = this.reportRenderer.renderAnalysisReport(analysisData.data, analysisData.fileName);
            this.reportContainer.innerHTML = renderResult.html;
            renderResult.postRender();
        } else if (analysisData.type === 'comparison') {
            const renderResult = this.reportRenderer.renderComparisonReport(analysisData.data, analysisData.file1Name, analysisData.file2Name);
            this.reportContainer.innerHTML = renderResult.html;
            renderResult.postRender();
        }
        this.exportButtons.classList.remove('hidden');
    }

    showLoading(message) {
        this.reportContainer.innerHTML = '';
        this.exportButtons.classList.add('hidden');
        this.loadingIndicator.classList.remove('hidden');
        this.loadingIndicator.querySelector('p').textContent = message;
    }

    hideLoading() {
        this.loadingIndicator.classList.add('hidden');
    }

    hideReport() {
        this.reportContainer.innerHTML = '';
        this.exportButtons.classList.add('hidden');
    }

    showMessage(message, isError = false) {
        this.messageText.textContent = message;
        this.messageBox.style.display = 'flex';
        this.messageBox.className = `message-box ${isError ? 'bg-red-500' : 'bg-green-500'}`;
        
        // Auto-hide after 5 seconds
        setTimeout(() => this.hideMessage(), 5000);
    }

    hideMessage() {
        this.messageBox.style.display = 'none';
    }

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