import { marked } from "https://cdn.jsdelivr.net/npm/marked/marked.min.js";

// Utility to handle form and report display
const form = document.getElementById('analysis-form');
const pcapFile = document.getElementById('pcap-file');
const llmModelSelect = document.getElementById('llm-model');
const reportContainer = document.getElementById('report-container');
const loadingIndicator = document.getElementById('loading-indicator');

let config = {}; // Store the loaded configuration

// Function to fetch the YAML config file
async function fetchConfig() {
    try {
        const response = await fetch('/config.yaml');
        if (!response.ok) {
            throw new Error(`Failed to load config.yaml`);
        }
        const text = await response.text();
        return jsyaml.load(text);
    } catch (e) {
        console.error("Error fetching config:", e);
        return null;
    }
}

// Function to populate the LLM model dropdown
async function populateLlmModels() {
    config = await fetchConfig();
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
        alert('Please select a PCAP file.');
        loadingIndicator.style.display = 'none';
        return;
    }

    try {
        const pcapData = await file.text(); // Assuming PCAP is text-based for this mock
        
        const response = await fetch('/api/analyze', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Session-ID': sessionId,
            },
            body: JSON.stringify({
                pcap_data: pcapData,
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
