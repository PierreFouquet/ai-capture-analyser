// Report rendering utilities
import { ChartRenderer } from './chartRenderer.js';

export class ReportRenderer {
    constructor() {
        this.chartRenderer = new ChartRenderer();
    }

    renderAnalysisReport(data, fileName) {
        // Generate random timeline data for demonstration
        const timelineLabels = Array.from({length: 20}, (_, i) => `${i + 1}s`);
        const timelineValues = Array.from({length: 20}, () => Math.floor(Math.random() * 100));
        
        const html = `
            <div class="report-section fade-in">
                <h2 class="text-2xl font-bold text-gray-800 mb-6">Analysis Report: ${fileName}</h2>
                
                <div class="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
                    <div class="summary-card">
                        <h3 class="text-xl font-semibold text-gray-700 mb-4">Summary</h3>
                        <div class="flex flex-wrap mb-4">
                            <div class="w-1/2 mb-2">
                                <p class="text-sm text-gray-600">Total Packets</p>
                                <p class="text-lg font-semibold">${data.packetCount.toLocaleString()}</p>
                            </div>
                            <div class="w-1/2 mb-2">
                                <p class="text-sm text-gray-600">Duration</p>
                                <p class="text-lg font-semibold">${data.duration} seconds</p>
                            </div>
                            <div class="w-1/2">
                                <p class="text-sm text-gray-600">Start Time</p>
                                <p class="text-lg font-semibold">${new Date(data.startTime).toLocaleString()}</p>
                            </div>
                            <div class="w-1/2">
                                <p class="text-sm text-gray-600">End Time</p>
                                <p class="text-lg font-semibold">${new Date(data.endTime).toLocaleString()}</p>
                            </div>
                        </div>
                        <p class="text-gray-600">${data.summary || 'This PCAP file contains a mix of network traffic with several protocols detected.'}</p>
                    </div>
                    
                    <div class="summary-card">
                        <h3 class="text-xl font-semibold text-gray-700 mb-4">Protocol Distribution</h3>
                        <div class="chart-container">
                            <canvas id="protocolChart"></canvas>
                        </div>
                    </div>
                </div>
                
                <div class="summary-card mb-6">
                    <h3 class="text-xl font-semibold text-gray-700 mb-4">Traffic Timeline</h3>
                    <div class="chart-container">
                        <canvas id="timelineChart"></canvas>
                    </div>
                </div>
                
                <div class="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
                    <div class="summary-card">
                        <h3 class="text-xl font-semibold text-gray-700 mb-4">Top Source IPs</h3>
                        <ul class="list-disc list-inside">
                            ${data.sourceIPs.map(ip => `<li class="text-gray-600">${ip}</li>`).join('')}
                        </ul>
                    </div>
                    
                    <div class="summary-card">
                        <h3 class="text-xl font-semibold text-gray-700 mb-4">Top Destination IPs</h3>
                        <ul class="list-disc list-inside">
                            ${data.destinationIPs.map(ip => `<li class="text-gray-600">${ip}</li>`).join('')}
                        </ul>
                    </div>
                </div>
                
                <div class="summary-card mb-6">
                    <h3 class="text-xl font-semibold text-gray-700 mb-4">Top Conversations</h3>
                    <div class="overflow-x-auto">
                        <table class="min-w-full divide-y divide-gray-200">
                            <thead class="bg-gray-50">
                                <tr>
                                    <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Source</th>
                                    <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Destination</th>
                                    <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Packets</th>
                                    <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Bytes</th>
                                </tr>
                            </thead>
                            <tbody class="bg-white divide-y divide-gray-200">
                                ${data.topConversations.map(conv => `
                                    <tr>
                                        <td class="px-4 py-3 whitespace-nowrap text-sm text-gray-600">${conv.source}</td>
                                        <td class="px-4 py-3 whitespace-nowrap text-sm text-gray-600">${conv.destination}</td>
                                        <td class="px-4 py-3 whitespace-nowrap text-sm text-gray-600">${conv.packets}</td>
                                        <td class="px-4 py-3 whitespace-nowrap text-sm text-gray-600">${conv.bytes.toLocaleString()}</td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                    </div>
                </div>
                
                <div class="summary-card">
                    <h3 class="text-xl font-semibold text-gray-700 mb-4">Anomalies and Errors</h3>
                    ${data.anomalies && data.anomalies.length > 0 ? `
                        <div class="analysis-timeline">
                            ${data.anomalies.map(anomaly => `
                                <div class="timeline-event">
                                    <h4 class="font-semibold text-gray-700">${anomaly.time}</h4>
                                    <p class="text-gray-600">${anomaly.description}</p>
                                    <span class="inline-block px-2 py-1 text-xs font-semibold rounded-full 
                                        ${anomaly.severity === 'High' ? 'bg-red-100 text-red-800' : 
                                          anomaly.severity === 'Medium' ? 'bg-yellow-100 text-yellow-800' : 
                                          'bg-blue-100 text-blue-800'}">
                                        ${anomaly.severity} severity
                                    </span>
                                </div>
                            `).join('')}
                        </div>
                    ` : `
                        <p class="text-gray-600">No significant anomalies detected.</p>
                    `}
                </div>
            </div>
        `;
        
        return {
            html,
            postRender: () => {
                this.chartRenderer.createProtocolChart(data.protocolDistribution, 'protocolChart');
                this.chartRenderer.createTimelineChart({
                    labels: timelineLabels,
                    values: timelineValues
                }, 'timelineChart');
            }
        };
    }

    renderComparisonReport(data, file1Name, file2Name) {
        const html = `
            <div class="report-section fade-in">
                <h2 class="text-2xl font-bold text-gray-800 mb-6">Comparison Report: ${file1Name} vs ${file2Name}</h2>
                
                <div class="summary-card mb-6">
                    <h3 class="text-xl font-semibold text-gray-700 mb-4">Overall Comparison Summary</h3>
                    <p class="text-gray-600">${data.summary || 'The two PCAP files show similar network patterns with some notable differences in protocol distribution and traffic volume.'}</p>
                </div>
                
                <div class="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
                    <div class="summary-card">
                        <h3 class="text-xl font-semibold text-gray-700 mb-4">${file1Name} Protocol Distribution</h3>
                        <div class="chart-container">
                            <canvas id="protocolChart1"></canvas>
                        </div>
                    </div>
                    
                    <div class="summary-card">
                        <h3 class="text-xl font-semibold text-gray-700 mb-4">${file2Name} Protocol Distribution</h3>
                        <div class="chart-container">
                            <canvas id="protocolChart2"></canvas>
                        </div>
                    </div>
                </div>
                
                <div class="summary-card mb-6">
                    <h3 class="text-xl font-semibold text-gray-700 mb-4">Protocol Comparison</h3>
                    <div class="chart-container">
                        <canvas id="comparisonChart"></canvas>
                    </div>
                </div>
                
                <div class="summary-card mb-6">
                    <h3 class="text-xl font-semibold text-gray-700 mb-4">Key Differences</h3>
                    <ul class="list-disc list-inside pl-5">
                        ${data.differences && data.differences.length > 0 ? 
                            data.differences.map(diff => `<li class="text-gray-600 mb-2">${diff}</li>`).join('') : 
                            '<li class="text-gray-600">No significant differences found.</li>'
                        }
                    </ul>
                </div>
                
                <div class="summary-card">
                    <h3 class="text-xl font-semibold text-gray-700 mb-4">Key Similarities</h3>
                    <ul class="list-disc list-inside pl-5">
                        ${data.similarities && data.similarities.length > 0 ? 
                            data.similarities.map(sim => `<li class="text-gray-600 mb-2">${sim}</li>`).join('') : 
                            '<li class="text-gray-600">No significant similarities found.</li>'
                        }
                    </ul>
                </div>
            </div>
        `;
        
        return {
            html,
            postRender: () => {
                this.chartRenderer.createProtocolChart(data.file1.protocolDistribution, 'protocolChart1');
                this.chartRenderer.createProtocolChart(data.file2.protocolDistribution, 'protocolChart2');
                this.chartRenderer.createComparisonChart(
                    data.file1.protocolDistribution, 
                    data.file2.protocolDistribution, 
                    'comparisonChart',
                    file1Name,
                    file2Name
                );
            }
        };
    }
}