// Backend communication utilities
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

let config = { llm_models, llm_settings, llm_prompts }; // Use the imported config

// Function to show a custom message box
function showMessage(message) {
    messageText.textContent = message;
    messageBox.style.display = 'flex';
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
async function pollStatus(sessionId, endpoint) {
    const statusResponse = await fetch(endpoint, {
        headers: { 'X-Session-ID': sessionId }
    });
    const statusResult = await statusResponse.json();

    if (statusResult.status === 'complete') {
        loadingIndicator.style.display = 'none';
        reportContainer.innerHTML = marked(statusResult.result.report);
    } else if (statusResult.status === 'error') {
        loadingIndicator.style.display = 'none';
        reportContainer.innerHTML = `<p class="error-message">Error: ${statusResult.result.error}</p>`;
    } else {
        setTimeout(() => pollStatus(sessionId, endpoint), 2000); // Poll every 2 seconds
    }
}

// Handle single file analysis submission
startAnalysisBtn.addEventListener('click', async (e) => {
    e.preventDefault();
    
    // Clear previous report and show loading indicator
    reportContainer.innerHTML = '';
    loadingIndicator.style.display = 'block';

    const file = pcapFile1.files[0];
    const llmModelKey = llmModelSelect1.value;
    const sessionId = 'pcap-analysis-' + Date.now();

    if (!file) {
        showMessage('Please select a PCAP file for analysis.');
        loadingIndicator.style.display = 'none';
        return;
    }

    try {
        const arrayBuffer = await file.arrayBuffer();
        const base64PcapData = btoa(String.fromCharCode(...new Uint8Array(arrayBuffer)));
        
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
            pollStatus(sessionId, '/api/analyze/status');
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
    loadingIndicator.style.display = 'block';
    
    const file1 = pcapFile2.files[0];
    const file2 = pcapFile3.files[0];
    const llmModelKey = llmModelSelect2.value;
    const sessionId = 'pcap-comparison-' + Date.now();

    if (!file1 || !file2) {
        showMessage('Please select two PCAP files for comparison.');
        loadingIndicator.style.display = 'none';
        return;
    }

    try {
        const arrayBuffer1 = await file1.arrayBuffer();
        const base64PcapData1 = btoa(String.fromCharCode(...new Uint8Array(arrayBuffer1)));

        const arrayBuffer2 = await file2.arrayBuffer();
        const base64PcapData2 = btoa(String.fromCharCode(...new Uint8Array(arrayBuffer2)));

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
            pollStatus(sessionId, '/api/compare/status');
        } else {
            loadingIndicator.style.display = 'none';
            reportContainer.innerHTML = `<p class="error-message">Error from server: ${result.error || response.statusText}</p>`;
        }
    } catch (e) {
        loadingIndicator.style.display = 'none';
        reportContainer.innerHTML = `<p class="error-message">An unexpected error occurred: ${e.message}</p>`;
    }
});