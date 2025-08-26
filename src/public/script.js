// public/script.js

document.addEventListener('DOMContentLoaded', () => {
    const startAnalysisBtn = document.getElementById('start-analysis-btn');
    const startComparisonBtn = document.getElementById('start-comparison-btn');
    const checkStatusBtn = document.getElementById('check-status-btn');
    const statusCard = document.getElementById('status-card');
    const jobStatusSpan = document.getElementById('job-status');
    const jobIdDisplay = document.getElementById('job-id-display');
    const reportOutput = document.getElementById('report-output');
    const loadingIndicator = document.getElementById('loading-indicator');
    const modelSelect1 = document.getElementById('model-select-1');
    const modelSelect2 = document.getElementById('model-select-2');
    
    let currentJobId = null;

    // Fetch the config to populate the model selection dropdowns
    async function fetchConfig() {
        try {
            const response = await fetch('/config.yaml');
            if (!response.ok) {
                throw new Error('Failed to load config.yaml');
            }
            const configText = await response.text();
            const models = parseYaml(configText).llm_models;
            populateModelSelects(models);
        } catch (error) {
            console.error('Error fetching config:', error);
            alert('Failed to load models. Please check the config.yaml file.');
        }
    }

    // A simple YAML parser for the config file
    function parseYaml(yamlString) {
        const lines = yamlString.split('\n').filter(line => line.trim() !== '' && !line.trim().startsWith('#'));
        let result = {};
        let currentSection = null;
        let indentLevel = 0;

        lines.forEach(line => {
            const indent = line.match(/^\s*/)[0].length;
            const key = line.trim().split(':')[0].trim();
            const value = line.trim().split(':').slice(1).join(':').trim().replace(/['"]+/g, '');

            if (indent === 0) {
                if (key.endsWith('s')) {
                    currentSection = key;
                    result[currentSection] = {};
                } else {
                    result[key] = value;
                }
            } else if (currentSection && indent === 2) {
                result[currentSection][key] = {};
                indentLevel = 2;
            } else if (currentSection && indent > indentLevel) {
                const parentKey = Object.keys(result[currentSection]).pop();
                if (parentKey) {
                    result[currentSection][parentKey][key] = value;
                }
            }
        });
        return result;
    }

    // Populate dropdowns with model names from the config
    function populateModelSelects(models) {
        const modelKeys = Object.keys(models);
        modelKeys.forEach(key => {
            const option1 = document.createElement('option');
            option1.value = key;
            option1.textContent = models[key].cloudflare_name;
            modelSelect1.appendChild(option1);

            const option2 = document.createElement('option');
            option2.value = key;
            option2.textContent = models[key].cloudflare_name;
            modelSelect2.appendChild(option2);
        });
    }

    // Parses a PCAP file into a human-readable text snippet
    async function parsePcapFile(file) {
        if (!file) return '';
        
        const buffer = await file.arrayBuffer();
        const packets = pcap.parse(buffer);
        
        let snippet = '';
        packets.forEach((packet, index) => {
            const timestamp = new Date(packet.timestamp.getTime()).toISOString();
            const dataView = new DataView(packet.payload);
            
            // This is a simplified parsing. A real-world app would do deeper analysis.
            const sourceIP = `${(dataView.getUint8(12))}.${(dataView.getUint8(13))}.${(dataView.getUint8(14))}.${(dataView.getUint8(15))}`;
            const destIP = `${(dataView.getUint8(16))}.${(dataView.getUint8(17))}.${(dataView.getUint8(18))}.${(dataView.getUint8(19))}`;

            snippet += `Packet ${index + 1}: Timestamp=${timestamp}, Source=${sourceIP}, Destination=${destIP}\n`;
        });

        return snippet;
    }

    // Starts an analysis job and polls for status
    async function startJob(jobType, pcapData1, pcapData2 = null) {
        loadingIndicator.classList.remove('hidden');
        reportOutput.innerHTML = '';
        jobStatusSpan.textContent = 'Starting...';

        const requestBody = {
            job_type: jobType,
            pcap_data: pcapData1,
            pcap_data2: pcapData2
        };

        try {
            const response = await fetch('/start-job', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(requestBody)
            });

            const data = await response.json();
            if (response.ok) {
                currentJobId = data.jobId;
                jobIdDisplay.textContent = `Job ID: ${currentJobId}`;
                statusCard.classList.remove('hidden');
                pollForStatus();
            } else {
                alert(`Error: ${data.error}`);
                loadingIndicator.classList.add('hidden');
            }
        } catch (error) {
            console.error('Failed to start job:', error);
            alert('Failed to start job. Check the console for details.');
            loadingIndicator.classList.add('hidden');
        }
    }

    // Polls the Worker for the job status
    function pollForStatus() {
        const interval = setInterval(async () => {
            if (!currentJobId) {
                clearInterval(interval);
                return;
            }

            try {
                const response = await fetch(`/get-status/${currentJobId}`);
                const data = await response.json();
                jobStatusSpan.textContent = data.status;

                if (data.status === 'complete') {
                    clearInterval(interval);
                    loadingIndicator.classList.add('hidden');
                    renderReport(data.report);
                } else if (data.status === 'failed') {
                    clearInterval(interval);
                    loadingIndicator.classList.add('hidden');
                    reportOutput.innerHTML = `<p class="text-red-600">Job failed: ${data.error || 'Unknown error'}</p>`;
                }
            } catch (error) {
                console.error('Failed to poll status:', error);
                clearInterval(interval);
                loadingIndicator.classList.add('hidden');
                reportOutput.innerHTML = `<p class="text-red-600">Failed to get status.</p>`;
            }
        }, 3000); // Poll every 3 seconds
    }

    // Renders the final LLM-generated report
    function renderReport(report) {
        if (!report) {
            reportOutput.innerHTML = '<p class="text-gray-500">No report data available.</p>';
            return;
        }

        let html = `
            <div class="report-section mb-6">
                <h3 class="text-lg font-bold text-gray-800 mb-2">Summary</h3>
                <p>${report.summary || 'N/A'}</p>
            </div>
            <div class="report-section mb-6">
                <h3 class="text-lg font-bold text-gray-800 mb-2">Anomalies and Errors</h3>
                <ul>
                    ${report.anomalies_and_errors && report.anomalies_and_errors.length > 0 ? report.anomalies_and_errors.map(item => `<li>${item}</li>`).join('') : '<li>N/A</li>'}
                </ul>
            </div>
            <div class="report-section mb-6">
                <h3 class="text-lg font-bold text-gray-800 mb-2">SIP/RTP Information</h3>
                <p>${report.sip_rtp_info || 'N/A'}</p>
            </div>
            <div class="report-section mb-6">
                <h3 class="text-lg font-bold text-gray-800 mb-2">Important Timestamps/Packets</h3>
                <p>${report.important_timestamps_packets || 'N/A'}</p>
            </div>
        `;

        reportOutput.innerHTML = html;
    }

    // Event listeners
    startAnalysisBtn.addEventListener('click', async () => {
        const file = document.getElementById('pcap-file-1').files[0];
        if (!file) {
            alert('Please select a file to analyze.');
            return;
        }
        const pcapData = await parsePcapFile(file);
        await startJob('analysis', pcapData);
    });

    startComparisonBtn.addEventListener('click', async () => {
        const file1 = document.getElementById('pcap-file-2').files[0];
        const file2 = document.getElementById('pcap-file-3').files[0];
        if (!file1 || !file2) {
            alert('Please select two files to compare.');
            return;
        }
        const pcapData1 = await parsePcapFile(file1);
        const pcapData2 = await parsePcapFile(file2);
        await startJob('comparison', pcapData1, pcapData2);
    });

    checkStatusBtn.addEventListener('click', () => {
        if (currentJobId) {
            pollForStatus();
        } else {
            alert('No job has been started yet.');
        }
    });

    fetchConfig();
});
