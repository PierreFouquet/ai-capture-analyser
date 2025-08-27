// public/script.js
import { marked } from "https://cdn.jsdelivr.net/npm/marked/marked.min.js";
import { llm_models, llm_settings, llm_prompts } from "./config.js";

// Utility to handle form and report display
const form = document.getElementById('analysis-form');
const pcapFile = document.getElementById('pcap-file');
const llmModelSelect = document.getElementById('llm-model');
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

// Function to populate the LLM model dropdown
function populateLlmModels() {
    if (config && config.llm_models) {
        const models = Object.entries(config.llm_models).map(([key, value]) => ({
            key,
            name: value.name
        }));
        llmModelSelect.innerHTML = '';
        models.forEach(model => {
            const option = document.createElement('option');
            option.value = model.key;
            option.textContent = model.name;
            llmModelSelect.appendChild(option);
        });
    } else {
        console.error("No LLM models available in config.");
    }
}

// Call the function on page load
window.onload = populateLlmModels;

// Handle form submission
form.addEventListener('submit', async (e) => {
    e.preventDefault();
    
    // Clear previous report and show loading indicator
    reportContainer.innerHTML = '';
    loadingIndicator.style.display = 'block';

    const file = pcapFile.files[0];
    const llmModelKey = llmModelSelect.value;
    const sessionId = 'pcap-analysis-' + Date.now(); // Create a unique session ID

    if (!file) {
        showMessage('Please select a PCAP file.');
        loadingIndicator.style.display = 'none';
        return;
    }

    try {
        // Read the file as an ArrayBuffer since PCAP files are binary
        const arrayBuffer = await file.arrayBuffer();
        
        // Convert ArrayBuffer to Base64 string for safe transmission
        const base64PcapData = btoa(
            String.fromCharCode(...new Uint8Array(arrayBuffer))
        );
        
        const response = await fetch('/api/analyze', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Session-ID': sessionId,
            },
            body: JSON.stringify({
                pcap_data: base64PcapData,
                file_name: file.name,
                llm_model_key: llmModelKey,
            }),
        });

        const result = await response.json();

        if (response.ok) {
            // Poll the Durable Object for status
            const pollStatus = async () => {
                const statusResponse = await fetch('/api/analyze/status', {
                    headers: { 'X-Session-ID': sessionId }
                });
                const statusResult = await statusResponse.json();

                if (statusResult.status === 'complete') {
                    loadingIndicator.style.display = 'none';
                    reportContainer.innerHTML = statusResult.result.report;
                } else if (statusResult.status === 'error') {
                    loadingIndicator.style.display = 'none';
                    reportContainer.innerHTML = `<p class="error-message">Error: ${statusResult.result.error}</p>`;
                } else {
                    setTimeout(pollStatus, 2000); // Poll every 2 seconds
                }
            };
            
            // Start polling
            pollStatus();

        } else {
            loadingIndicator.style.display = 'none';
            reportContainer.innerHTML = `<p class="error-message">Error from server: ${result.error || response.statusText}</p>`;
        }

    } catch (e) {
        loadingIndicator.style.display = 'none';
        reportContainer.innerHTML = `<p class="error-message">An unexpected error occurred: ${e.message}</p>`;
    }
});
