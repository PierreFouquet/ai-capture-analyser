// Main application logic
import { llm_models, llm_settings } from './config.js';
import { PcapParser } from './pcapParser.js';
import { ReportRenderer } from './reportRenderer.js';
import { PDFExporter } from './pdfExporter.js';
import { Backend } from './backend.js'; // Import the new Backend class

export class PCAPAnalyzerApp {
    constructor() {
        this.pcapParser = new PcapParser();
        this.reportRenderer = new ReportRenderer();
        this.pdfExporter = new PDFExporter();
        this.backend = new Backend(); // Initialize the Backend class
        this.currentAnalysisData = null;
        
        this.initializeDOMElements();
        this.bindEvents();
        this.populateLlmModels();
    }

    initializeDOMElements() {
        this.pcapFile1 = document.getElementById('pcap-file-1');
        this.pcapFile2 = document.getElementById('pcap-file-2');
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
        this.messageClose.addEventListener('click', () => this.hideMessage());
        this.exportPdfBtn.addEventListener('click', () => this.exportPDF());
        this.exportJsonBtn.addEventListener('click', () => this.exportJSON());
    }

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

        this.llmModelSelect1.value = llm_settings.default_llm_model_analysis || models[0];
        this.llmModelSelect2.value = llm_settings.default_llm_model_comparison || models[0];
    }

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

    hideMessage() {
        this.messageBox.style.display = 'none';
    }

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
        this.showMessage('Analyzing PCAP file with LLM...', false);

        try {
            const analysisResult = await this.backend.analyzePcap(file, llmModelKey);

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

    async startComparison() {
        const file1 = this.pcapFile1.files[0];
        const file2 = this.pcapFile2.files[0];
        const llmModelKey = this.llmModelSelect2.value;

        if (!file1 || !file2) {
            this.showMessage('Please select two PCAP files for comparison.', true);
            return;
        }

        this.loadingIndicator.style.display = 'flex';
        this.reportContainer.innerHTML = '';
        this.exportButtons.classList.add('hidden');
        this.showMessage('Comparing PCAP files with LLM...', false);

        try {
            const comparisonResult = await this.backend.comparePcaps(file1, file2, llmModelKey);

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

document.addEventListener('DOMContentLoaded', () => {
    window.pcapAnalyzerApp = new PCAPAnalyzerApp();
});
