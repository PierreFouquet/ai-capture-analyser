// Chart rendering utilities

export class ChartRenderer {
    constructor() {
        this.colors = [
            'rgba(54, 162, 235, 0.7)',
            'rgba(255, 99, 132, 0.7)',
            'rgba(255, 206, 86, 0.7)',
            'rgba(75, 192, 192, 0.7)',
            'rgba(153, 102, 255, 0.7)',
            'rgba(255, 159, 64, 0.7)'
        ];
    }

    createProtocolChart(protocolData, canvasId) {
        // Add a defensive check for protocolData
        if (!protocolData) {
            console.error(`No protocol data provided for canvas with id: ${canvasId}`);
            // Return early to prevent the TypeError
            return;
        }
        
        const ctx = document.getElementById(canvasId);
        if (!ctx) {
            console.error(`Canvas element with id ${canvasId} not found`);
            return null;
        }
        
        const labels = Object.keys(protocolData);
        const data = Object.values(protocolData);
        
        return new Chart(ctx.getContext('2d'), {
            type: 'doughnut',
            data: {
                labels: labels,
                datasets: [{
                    data: data,
                    backgroundColor: this.colors.slice(0, labels.length),
                    borderColor: this.colors.map(color => color.replace('0.7', '1')),
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'right',
                    },
                    tooltip: {
                        callbacks: {
                            label: function(tooltipItem) {
                                let label = tooltipItem.label || '';
                                if (label) {
                                    label += ': ';
                                }
                                label += tooltipItem.raw.toFixed(2) + '%';
                                return label;
                            }
                        }
                    }
                }
            }
        });
    }

    createComparisonChart(data1, data2, canvasId, label1, label2) {
        const ctx = document.getElementById(canvasId);
        if (!ctx) {
            console.error(`Canvas element with id ${canvasId} not found`);
            return null;
        }
        
        const protocols = [...new Set([...Object.keys(data1 || {}), ...Object.keys(data2 || {})])];
        
        return new Chart(ctx.getContext('2d'), {
            type: 'bar',
            data: {
                labels: protocols,
                datasets: [
                    {
                        label: label1,
                        data: protocols.map(protocol => data1[protocol] || 0),
                        backgroundColor: this.colors[0]
                    },
                    {
                        label: label2,
                        data: protocols.map(protocol => data2[protocol] || 0),
                        backgroundColor: this.colors[1]
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        title: {
                            display: true,
                            text: 'Percentage (%)'
                        }
                    }
                }
            }
        });
    }

    createTimelineChart(timelineData, canvasId) {
        const ctx = document.getElementById(canvasId);
        if (!ctx) {
            console.error(`Canvas element with id ${canvasId} not found`);
            return null;
        }
        
        const labels = Object.keys(timelineData);
        const data = Object.values(timelineData);
        
        return new Chart(ctx.getContext('2d'), {
            type: 'line',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Packets per Second',
                    data: data,
                    borderColor: this.colors[3],
                    backgroundColor: 'rgba(75, 192, 192, 0.2)',
                    fill: true,
                    tension: 0.1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        title: {
                            display: true,
                            text: 'Packets'
                        }
                    },
                    x: {
                        title: {
                            display: true,
                            text: 'Time (seconds)'
                        }
                    }
                }
            }
        });
    }

    destroyChart(chart) {
        if (chart) {
            chart.destroy();
        }
    }
}
