// public/script.js
import { llm_models, llm_settings, llm_prompts } from "./config.js";

// Utility to handle form and report display
const pcapFile1 = document.getElementById('pcap-file-1');
const pcapFile2 = document.getElementById('pcap-file-2');
const pcapFile3 = document.getElementById('pcap-file-3');
const llmModelSelect1 = document.getElementById('model-select-1');
const llmModelSelect2 = document.getElementById('model-select-2');
const startAnalysisBtn = document.getElementById('start-analysis-btn');
const startComparisonBtn = document.getElementById('start-comparison-btn');
const reportContainer = document.getElementById('report-container');
const loadingIndicator = document.getElementById('loading-indicator');
const messageBox = document.getElementById('message-box');
const messageText = document.getElementById('message-text');
const messageClose = document.getElementById('message-close');
const exportButtons = document.getElementById('export-buttons');
const exportPdfBtn = document.getElementById('export-pdf');
const exportJsonBtn = document.getElementById('export-json');

import { PcapParser } from './pcapParser.js';
import { ReportRenderer } from './reportRenderer.js';
import { PDFExporter } from './pdfExporter.js';

const pcapParser = new PcapParser();
const reportRenderer = new ReportRenderer();
const pdfExporter = new PDFExporter();

let currentAnalysisData = null;

let config = { llm_models, llm_settings, llm_prompts }; // Use the imported config

// Function to show a custom message box
function showMessage(message, isError = false) {
    messageText.textContent = message;
    if (isError) {
        messageBox.classList.remove('bg-green-500');
        messageBox.classList.add('bg-red-500');
    } else {
        messageBox.classList.remove('bg-red-500');
        messageBox.classList.add('bg-green-500');
    }
    messageBox.style.display = 'flex';
    setTimeout(() => hideMessage(), 5000); // Hide after 5 seconds
}

// Function to hide the custom message box
function hideMessage() {
    messageBox.style.display = 'none';
}

// Event listener to close the message box
messageClose.addEventListener('click', hideMessage);

// Function to populate the LLM model dropdowns
function populateLlmModels() {
    if (config && config.llm_models) {
        const models = Object.entries(config.llm_models).map(([key, value]) => ({
            key,
            name: value.name
        }));
        
        // Populate analysis model dropdown
        llmModelSelect1.innerHTML = '';
        models.forEach(model => {
            const option = document.createElement('option');
            option.value = model.key;
            option.textContent = model.name;
            llmModelSelect1.appendChild(option);
        });
        llmModelSelect1.value = config.llm_settings.default_llm_model_analysis;

        // Populate comparison model dropdown
        llmModelSelect2.innerHTML = '';
        models.forEach(model => {
            const option = document.createElement('option');
            option.value = model.key;
            option.textContent = model.name;
            llmModelSelect2.appendChild(option);
        });
        llmModelSelect2.value = config.llm_settings.default_llm_model_comparison;

    } else {
        console.error("No LLM models available in config.");
    }
}

// Call the function on page load
window.onload = populateLlmModels;


// Generic polling function
async function pollStatus(sessionId, endpoint, isComparison) {
    const statusResponse = await fetch(endpoint, {
        headers: { 'X-Session-ID': sessionId }
    });
    const statusResult = await statusResponse.json();

    if (statusResult.status === 'complete') {
        loadingIndicator.style.display = 'none';
        
        let renderedReport;
        if (isComparison) {
            renderedReport = reportRenderer.renderComparisonReport(
                statusResult.result.report,
                statusResult.result.file_name1,
                statusResult.result.file_name2
            );
            currentAnalysisData = { 
                data: statusResult.result.report, 
                type: 'comparison', 
                file1Name: statusResult.result.file_name1, 
                file2Name: statusResult.result.file_name2
            };
        } else {
            renderedReport = reportRenderer.renderAnalysisReport(
                statusResult.result.report,
                statusResult.result.file_name
            );
            currentAnalysisData = { 
                data: statusResult.result.report, 
                type: 'analysis', 
                fileName: statusResult.result.file_name
            };
        }
        
        reportContainer.innerHTML = renderedReport;
        exportButtons.classList.remove('hidden');

    } else if (statusResult.status === 'error') {
        loadingIndicator.style.display = 'none';
        reportContainer.innerHTML = `<p class="error-message">Error: ${statusResult.result.error}</p>`;
        exportButtons.classList.add('hidden');
    } else {
        // Poll every 2 seconds
        setTimeout(() => pollStatus(sessionId, endpoint, isComparison), 2000);
    }
}

// Handle single file analysis submission
startAnalysisBtn.addEventListener('click', async (e) => {
    e.preventDefault();
    
    // Clear previous report and show loading indicator
    reportContainer.innerHTML = '';
    exportButtons.classList.add('hidden');
    loadingIndicator.style.display = 'flex';

    const file = pcapFile1.files[0];
    const llmModelKey = llmModelSelect1.value;
    const sessionId = 'pcap-analysis-' + Date.now();

    if (!file) {
        showMessage('Please select a PCAP file for analysis.', true);
        loadingIndicator.style.display = 'none';
        return;
    }

    try {
        const base64PcapData = await pcapParser.readAsBase64(file);
        
        const response = await fetch('/api/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-Session-ID': sessionId },
            body: JSON.stringify({
                pcap_data: base64PcapData,
                file_name: file.name,
                llm_model_key: llmModelKey,
            }),
        });

        const result = await response.json();

        if (response.ok) {
            pollStatus(sessionId, '/api/analyze/status', false);
        } else {
            loadingIndicator.style.display = 'none';
            reportContainer.innerHTML = `<p class="error-message">Error from server: ${result.error || response.statusText}</p>`;
        }
    } catch (e) {
        loadingIndicator.style.display = 'none';
        reportContainer.innerHTML = `<p class="error-message">An unexpected error occurred: ${e.message}</p>`;
    }
});

// Handle file comparison submission
startComparisonBtn.addEventListener('click', async (e) => {
    e.preventDefault();

    reportContainer.innerHTML = '';
    exportButtons.classList.add('hidden');
    loadingIndicator.style.display = 'flex';
    
    const file1 = pcapFile2.files[0];
    const file2 = pcapFile3.files[0];
    const llmModelKey = llmModelSelect2.value;
    const sessionId = 'pcap-comparison-' + Date.now();

    if (!file1 || !file2) {
        showMessage('Please select two PCAP files for comparison.', true);
        loadingIndicator.style.display = 'none';
        return;
    }

    try {
        const base64PcapData1 = await pcapParser.readAsBase64(file1);
        const base64PcapData2 = await pcapParser.readAsBase64(file2);

        const response = await fetch('/api/compare', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-Session-ID': sessionId },
            body: JSON.stringify({
                pcap_data1: base64PcapData1,
                file_name1: file1.name,
                pcap_data2: base64PcapData2,
                file_name2: file2.name,
                llm_model_key: llmModelKey,
            }),
        });
        
        const result = await response.json();

        if (response.ok) {
            pollStatus(sessionId, '/api/compare/status', true);
        } else {
            loadingIndicator.style.display = 'none';
            reportContainer.innerHTML = `<p class="error-message">Error from server: ${result.error || response.statusText}</p>`;
        }
    } catch (e) {
        loadingIndicator.style.display = 'none';
        reportContainer.innerHTML = `<p class="error-message">An unexpected error occurred: ${e.message}</p>`;
    }
});

// Export buttons event listeners
exportPdfBtn.addEventListener('click', () => {
    if (currentAnalysisData.type === 'analysis') {
        pdfExporter.exportAnalysisReport(
            currentAnalysisData.data,
            currentAnalysisData.fileName
        );
    } else if (currentAnalysisData.type === 'comparison') {
        pdfExporter.exportComparisonReport(
            currentAnalysisData.data,
            currentAnalysisData.file1Name,
            currentAnalysisData.file2Name
        );
    }
});

exportJsonBtn.addEventListener('click', () => {
    if (currentAnalysisData) {
        const dataStr = JSON.stringify(currentAnalysisData.data, null, 2);
        const dataUri = 'data:application/json;charset=utf-8,' + encodeURIComponent(dataStr);
        const exportFileDefaultName = `pcap-report-${Date.now()}.json`;

        const linkElement = document.createElement('a');
        linkElement.setAttribute('href', dataUri);
        linkElement.setAttribute('download', exportFileDefaultName);
        linkElement.click();
        showMessage('JSON report downloaded successfully', false);
    }
});
