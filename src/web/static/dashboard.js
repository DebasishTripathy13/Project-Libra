// ProjectLibra Dashboard JavaScript
// Real-time updates and interactivity

let expertMode = false;
let updateInterval;
let threatChart, resourceChart, severityPieChart;

// Initialize dashboard
document.addEventListener('DOMContentLoaded', function () {
    initCharts();
    initEventListeners();
    startRealTimeUpdates();
    loadDashboardData();
});

// Initialize Charts
function initCharts() {
    // Severity Pie Chart
    const pieCtx = document.getElementById('severityPieChart');
    if (pieCtx) {
        severityPieChart = new Chart(pieCtx, {
            type: 'doughnut',
            data: {
                labels: ['Critical', 'High', 'Medium', 'Low'],
                datasets: [{
                    data: [0, 0, 0, 0],
                    backgroundColor: [
                        'rgba(239, 68, 68, 0.8)',   // Critical - Red
                        'rgba(245, 158, 11, 0.8)',  // High - Orange
                        'rgba(59, 130, 246, 0.8)',  // Medium - Blue
                        'rgba(107, 114, 128, 0.8)'  // Low - Gray
                    ],
                    borderColor: [
                        'rgb(239, 68, 68)',
                        'rgb(245, 158, 11)',
                        'rgb(59, 130, 246)',
                        'rgb(107, 114, 128)'
                    ],
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: false
                    },
                    tooltip: {
                        callbacks: {
                            label: function (context) {
                                let label = context.label || '';
                                let value = context.parsed;
                                let total = context.dataset.data.reduce((a, b) => a + b, 0);
                                let percentage = total > 0 ? ((value / total) * 100).toFixed(1) : 0;
                                return label + ': ' + value + ' (' + percentage + '%)';
                            }
                        }
                    }
                }
            }
        });
    }

    // Threat Level Timeline Chart
    const threatCtx = document.getElementById('threatChart');
    if (threatCtx) {
        threatChart = new Chart(threatCtx, {
            type: 'line',
            data: {
                labels: ['10h ago', '9h ago', '8h ago', '7h ago', '6h ago', '5h ago', '4h ago', '3h ago', '2h ago', '1h ago', 'Now'],
                datasets: [{
                    label: 'Threat Level',
                    data: [15, 28, 35, 32, 18, 12, 8, 29, 32, 24, 8],
                    borderColor: 'rgb(239, 68, 68)',
                    backgroundColor: 'rgba(239, 68, 68, 0.1)',
                    tension: 0.4,
                    fill: true
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        max: 100,
                        grid: { color: 'rgba(148, 163, 184, 0.1)' },
                        ticks: { color: '#94a3b8' }
                    },
                    x: {
                        grid: { color: 'rgba(148, 163, 184, 0.1)' },
                        ticks: { color: '#94a3b8' }
                    }
                }
            }
        });
    }

    // System Resources Chart
    const resourceCtx = document.getElementById('resourceChart');
    if (resourceCtx) {
        resourceChart = new Chart(resourceCtx, {
            type: 'bar',
            data: {
                labels: ['CPU', 'Memory', 'Disk'],
                datasets: [{
                    label: 'Usage %',
                    data: [0, 0, 0],
                    backgroundColor: [
                        'rgba(37, 99, 235, 0.8)',
                        'rgba(245, 158, 11, 0.8)',
                        'rgba(239, 68, 68, 0.8)'
                    ]
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        max: 100,
                        grid: { color: 'rgba(148, 163, 184, 0.1)' },
                        ticks: { color: '#94a3b8' }
                    },
                    x: {
                        grid: { display: false },
                        ticks: { color: '#94a3b8' }
                    }
                }
            }
        });
    }
}

// Initialize Event Listeners
function initEventListeners() {
    // Navigation
    document.querySelectorAll('.nav-link[data-section]').forEach(link => {
        link.addEventListener('click', function (e) {
            e.preventDefault();
            const section = this.getAttribute('data-section');
            if (section) {
                switchSection(section);

                // Update active state
                document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
                this.classList.add('active');
            }
        });
    });

    // Expert Mode Toggle
    document.getElementById('expertModeBtn')?.addEventListener('click', toggleExpertMode);

    // Generate Report Button
    document.getElementById('generateReportBtn')?.addEventListener('click', function () {
        const modal = new bootstrap.Modal(document.getElementById('reportModal'));
        modal.show();
    });

    // Download Report Button
    document.getElementById('downloadReportBtn')?.addEventListener('click', generateReport);

    // Clear Logs Button
    document.getElementById('clearLogsBtn')?.addEventListener('click', clearLogs);

    // Log Filter
    document.getElementById('logFilter')?.addEventListener('input', filterLogs);

    // AI Analyze Button
    document.getElementById('aiAnalyzeBtn')?.addEventListener('click', analyzeLogsWithAI);

    // ML Status Button
    document.getElementById('mlStatusBtn')?.addEventListener('click', showMLStatus);

    // Sidebar ML Status link
    document.getElementById('sidebarMLStatus')?.addEventListener('click', (e) => {
        e.preventDefault();
        showMLStatus();
    });
}

// Switch Section
function switchSection(section) {
    document.querySelectorAll('.content-section').forEach(s => s.style.display = 'none');
    document.getElementById(`${section}-section`).style.display = 'block';

    // Load section-specific data
    switch (section) {
        case 'dashboard':
            loadDashboardData();
            break;
        case 'threats':
            loadThreats();
            break;
        case 'logs':
            loadLogs();
            break;
        case 'integrity':
            loadIntegrity();
            break;
        case 'system':
            loadSystemStatus();
            break;
        case 'updates':
            loadUpdates();
            break;
        case 'agents':
            loadAgents();
            break;
    }
}

// Load Dashboard Data
async function loadDashboardData() {
    try {
        // Load main dashboard stats
        const response = await fetch('/api/dashboard');
        const data = await response.json();

        // Update basic stats
        document.getElementById('stat-threats').textContent = data.active_threats || 0;
        document.getElementById('stat-logs').textContent = data.log_count || 0;
        document.getElementById('stat-health').textContent = data.health_status || 'Good';
        document.getElementById('stat-agents').textContent = data.active_agents || 5;

        // Load system metrics
        const metricsResponse = await fetch('/api/system/metrics');
        const metrics = await metricsResponse.json();

        // Update system metrics
        document.getElementById('cpu-percent').textContent = metrics.cpu_percent?.toFixed(1) + '%' || '0%';
        document.getElementById('mem-percent').textContent = metrics.memory_percent?.toFixed(1) + '%' || '0%';
        document.getElementById('disk-percent').textContent = metrics.disk_percent?.toFixed(1) + '%' || '0%';
        document.getElementById('net-sent').textContent = metrics.network_sent_mb?.toFixed(2) + ' MB' || '0 MB';
        document.getElementById('net-recv').textContent = metrics.network_recv_mb?.toFixed(2) + ' MB' || '0 MB';

        // Update network bars
        document.getElementById('net-sent-bar').style.width = Math.min(metrics.network_sent_mb || 0, 100) + '%';
        document.getElementById('net-recv-bar').style.width = Math.min(metrics.network_recv_mb || 0, 100) + '%';

        // Update network stats (simulate)
        document.getElementById('conn-count').textContent = Math.floor(Math.random() * 50 + 10);
        document.getElementById('packets-sec').textContent = Math.floor(Math.random() * 1000 + 100);
        document.getElementById('bandwidth').textContent = (Math.random() * 10 + 5).toFixed(1);

        // Update uptime
        if (metrics.uptime_seconds) {
            const hours = Math.floor(metrics.uptime_seconds / 3600);
            const days = Math.floor(hours / 24);
            const displayHours = hours % 24;
            document.getElementById('uptime-display').textContent =
                days > 0 ? `${days}d ${displayHours}h` : `${hours}h`;
        }

        // Load integrity status
        const integrityResponse = await fetch('/api/integrity');
        const integrity = await integrityResponse.json();
        document.getElementById('integrity-verified').textContent = integrity.verified_records || 0;

        // Load logs to get severity distribution
        const logsResponse = await fetch('/api/logs?limit=100');
        const logs = await logsResponse.json();

        // Calculate severity distribution
        let critical = 0, high = 0, medium = 0, low = 0;
        logs.logs.forEach(log => {
            const level = log.level.toLowerCase();
            if (level === 'critical' || level === 'error') critical++;
            else if (level === 'warning') high++;
            else if (level === 'info') medium++;
            else low++;
        });

        // Update pie chart
        if (severityPieChart) {
            severityPieChart.data.datasets[0].data = [critical, high, medium, low];
            severityPieChart.update();
        }

        // Update severity badges
        document.getElementById('pie-critical').textContent = critical;
        document.getElementById('pie-high').textContent = high;
        document.getElementById('pie-medium').textContent = medium;
        document.getElementById('pie-low').textContent = low;

        // Update resource chart with real data
        if (resourceChart) {
            resourceChart.data.datasets[0].data = [
                metrics.cpu_percent || 0,
                metrics.memory_percent || 0,
                metrics.disk_percent || 0
            ];
            resourceChart.update();
        }

        // Update recent events
        const recentEvents = logs.logs.slice(0, 10).map(log => ({
            type: log.level,
            message: log.message,
            timestamp: log.timestamp,
            source: log.source
        }));
        updateRecentEvents(recentEvents);

    } catch (error) {
        console.error('Error loading dashboard:', error);
    }
}

// Update Recent Events
function updateRecentEvents(events) {
    const container = document.getElementById('recent-events');
    if (!container) return;

    document.getElementById('event-count').textContent = events.length;

    const severityIcon = {
        'critical': '<i class="bi bi-shield-fill-x text-danger"></i>',
        'error': '<i class="bi bi-x-circle-fill text-danger"></i>',
        'warning': '<i class="bi bi-exclamation-triangle-fill text-warning"></i>',
        'info': '<i class="bi bi-info-circle-fill text-primary"></i>',
        'debug': '<i class="bi bi-bug-fill text-secondary"></i>'
    };

    container.innerHTML = events.map(event => {
        const level = event.type?.toLowerCase() || 'info';
        const icon = severityIcon[level] || severityIcon['info'];

        return `
        <div class="p-3 mb-2 rounded glass-card-hover border border-white border-opacity-10 transition-all">
            <div class="d-flex align-items-center gap-3">
                <div class="p-2 rounded-circle bg-${level === 'critical' || level === 'error' ? 'danger' : 'secondary'} bg-opacity-10">
                    ${icon}
                </div>
                <div class="flex-grow-1 min-w-0">
                    <div class="d-flex justify-content-between align-items-baseline mb-1">
                        <span class="badge bg-secondary bg-opacity-10 text-secondary border border-secondary border-opacity-20 text-xs font-monospace">${escapeHtml(event.source || 'system')}</span>
                        <span class="text-secondary text-xs">${formatTime(event.timestamp)}</span>
                    </div>
                    <p class="mb-0 text-sm text-truncate text-white-75 font-monospace">${escapeHtml(event.message || '')}</p>
                </div>
            </div>
        </div>
    `}).join('') || '<div class="text-center py-5 text-secondary opacity-75"><i class="bi bi-inbox fs-4 d-block mb-2"></i>No recent events</div>';
}

// Load Threats
async function loadThreats() {
    try {
        const response = await fetch('/api/threats');
        const data = await response.json();

        const content = document.getElementById('threats-content');
        content.innerHTML = `
            <div class="table-responsive">
                <table class="table modern-table w-100">
                    <thead>
                        <tr>
                            <th>Severity</th>
                            <th>Type</th>
                            <th>Source</th>
                            <th>Confidence</th>
                            <th>Timestamp</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${data.threats.map(t => `
                            <tr>
                                <td><span class="badge bg-${getSeverityColor(t.severity)} bg-opacity-10 text-${getSeverityColor(t.severity)} border border-${getSeverityColor(t.severity)} border-opacity-25">${t.severity}</span></td>
                                <td class="fw-bold">${escapeHtml(t.type)}</td>
                                <td><code class="text-secondary">${escapeHtml(t.source)}</code></td>
                                <td>
                                    <div class="d-flex align-items-center gap-2">
                                        <div class="progress flex-grow-1" style="height: 4px; width: 50px;">
                                            <div class="progress-bar bg-${t.confidence > 0.8 ? 'danger' : 'warning'}" style="width: ${t.confidence * 100}%"></div>
                                        </div>
                                        <small>${(t.confidence * 100).toFixed(0)}%</small>
                                    </div>
                                </td>
                                <td class="text-secondary small">${formatTime(t.timestamp)}</td>
                                <td>
                                    <button class="btn btn-sm btn-outline-primary rounded-circle" onclick="viewThreatDetails('${t.id}')">
                                        <i class="bi bi-eye"></i>
                                    </button>
                                </td>
                            </tr>
                        `).join('') || '<tr><td colspan="6" class="text-center text-secondary py-4">No threats detected</td></tr>'}
                    </tbody>
                </table>
            </div>
        `;
    } catch (error) {
        console.error('Error loading threats:', error);
    }
}

// Load Logs
async function loadLogs() {
    try {
        const response = await fetch('/api/logs?limit=100');
        const data = await response.json();

        // Update log count badge
        const logCountBadge = document.getElementById('log-count');
        if (logCountBadge) {
            logCountBadge.textContent = data.logs.length;
        }

        const content = document.getElementById('logs-content');
        content.innerHTML = data.logs.map(log => `
            <div class="log-entry ${log.level} border-bottom border-white border-opacity-5 p-2 px-3 hover-bg-white hover-bg-opacity-05 transition-all" data-log="${escapeHtml(JSON.stringify(log))}">
                <div class="row align-items-center g-2">
                    <div class="col-md-2 col-3 text-secondary small font-monospace text-nowrap">
                        ${formatTime(log.timestamp).split(',')[1] || ''}
                    </div>
                    <div class="col-md-2 col-3">
                        <span class="badge bg-secondary bg-opacity-20 text-secondary border border-secondary border-opacity-25 w-100 font-monospace text-truncate">${log.source}</span>
                    </div>
                    <div class="col-md-8 col-6">
                        <div class="d-flex align-items-center gap-2">
                            ${log.level === 'critical' || log.level === 'error' ? '<i class="bi bi-circle-fill text-danger" style="font-size: 6px;"></i>' : ''}
                            <span class="text-break font-monospace small ${log.level === 'critical' ? 'text-danger fw-bold' : (log.level === 'error' ? 'text-danger' : 'text-light')}">
                                ${escapeHtml(log.message)}
                            </span>
                        </div>
                    </div>
                </div>
            </div>
        `).join('') || '<div class="p-4 text-center text-secondary">No logs available</div>';
    } catch (error) {
        console.error('Error loading logs:', error);
    }
}

// Load Integrity Status
async function loadIntegrity() {
    try {
        const content = document.getElementById('integrity-content');
        if (content) {
            content.innerHTML = '<div class="text-center py-5"><div class="spinner-border text-primary" role="status"></div><div class="mt-2 text-secondary">Verifying system integrity...</div></div>';
        }

        const response = await fetch('/api/integrity');
        const data = await response.json();

        const isHealthy = data.tampered_records === 0 && data.missing_records === 0;

        content.innerHTML = `
            <div class="glass-card mb-4 p-4 border-start border-4 ${isHealthy ? 'border-success' : 'border-danger'} bg-gradient-to-r from-gray-900 to-transparent">
                <div class="d-flex align-items-center">
                    <div class="rounded-circle p-3 mr-3 ${isHealthy ? 'bg-success' : 'bg-danger'} bg-opacity-20 text-${isHealthy ? 'success' : 'danger'}">
                        <i class="bi bi-${isHealthy ? 'check-circle' : 'shield-exclamation'}-fill fs-3"></i>
                    </div>
                    <div class="ms-3">
                        <h4 class="mb-1 text-white">Database Integrity: <span class="${isHealthy ? 'text-success' : 'text-danger'} fw-bold">${isHealthy ? 'SECURE' : 'COMPROMISED'}</span></h4>
                        <p class="mb-0 text-secondary small">Last scan completed just now • Hash verification active</p>
                    </div>
                </div>
            </div>
            
            <div class="row g-4 mb-4">
                <div class="col-md-4">
                    <div class="glass-card p-4 text-center h-100 position-relative overflow-hidden">
                        <i class="bi bi-file-earmark-check position-absolute top-0 end-0 p-3 opacity-10 fs-1"></i>
                        <h2 class="text-success mb-1 display-5 fw-bold">${data.verified_records}</h2>
                        <div class="text-secondary text-uppercase text-xs tracking-wider">Verified Records</div>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="glass-card p-4 text-center h-100 position-relative overflow-hidden">
                        <i class="bi bi-file-earmark-x position-absolute top-0 end-0 p-3 opacity-10 fs-1"></i>
                        <h2 class="text-warning mb-1 display-5 fw-bold">${data.missing_records}</h2>
                        <div class="text-secondary text-uppercase text-xs tracking-wider">Missing Records</div>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="glass-card p-4 text-center h-100 position-relative overflow-hidden">
                        <i class="bi bi-shield-slash position-absolute top-0 end-0 p-3 opacity-10 fs-1"></i>
                        <h2 class="text-danger mb-1 display-5 fw-bold">${data.tampered_records}</h2>
                        <div class="text-secondary text-uppercase text-xs tracking-wider">Tampered Records</div>
                    </div>
                </div>
            </div>
            
            ${data.tampered_ids && data.tampered_ids.length > 0 ? `
                <div class="glass-card p-0 overflow-hidden mt-4">
                    <div class="p-3 border-bottom border-white border-opacity-10 bg-danger bg-opacity-10">
                        <h6 class="mb-0 text-danger"><i class="bi bi-exclamation-triangle-fill me-2"></i>Compromised Record Details</h6>
                    </div>
                    <div class="list-group list-group-flush">
                        ${data.tampered_ids.map(id => `
                            <div class="list-group-item bg-transparent text-white border-white border-opacity-5 py-3 d-flex align-items-center">
                                <i class="bi bi-x-octagon text-danger me-3"></i>
                                <div>
                                    <div class="text-xs text-secondary text-uppercase mb-1">Record ID</div>
                                    <code class="text-danger fw-bold fs-6">${id}</code>
                                </div>
                                <button class="btn btn-sm btn-outline-danger ms-auto">Restore</button>
                            </div>
                        `).join('')}
                    </div>
                </div>
            ` : ''}
`;
    } catch (error) {
        console.error('Error loading integrity:', error);
    }
}

// Load System Status
async function loadSystemStatus() {
    try {
        const response = await fetch('/api/system/metrics');
        const data = await response.json();

        // Update progress bars
        updateResourceBar('cpu', data.cpu_percent);
        updateResourceBar('mem', data.memory_percent);
        updateResourceBar('disk', data.disk_percent);

        // Update network
        document.getElementById('network-io').textContent =
            `${(data.network_sent_mb + data.network_recv_mb).toFixed(1)} MB/s`;
        document.getElementById('network-detail').textContent =
            `↑ ${data.network_sent_mb.toFixed(1)} MB/s ↓ ${data.network_recv_mb.toFixed(1)} MB/s`;

        // Update details
        document.getElementById('system-details').innerHTML = `
            <div class="table-responsive">
                <table class="table modern-table table-sm mb-0">
                    <tbody>
                        <tr><td class="text-secondary">Hostname</td><td class="font-monospace text-primary">${data.hostname}</td></tr>
                        <tr><td class="text-secondary">Platform</td><td class="font-monospace">${data.platform}</td></tr>
                        <tr><td class="text-secondary">CPU Count</td><td class="font-monospace">${data.cpu_count} cores</td></tr>
                        <tr><td class="text-secondary">Total Memory</td><td class="font-monospace">${(data.memory_total / 1024 / 1024 / 1024).toFixed(2)} GB</td></tr>
                        <tr><td class="text-secondary">Total Disk</td><td class="font-monospace">${(data.disk_total / 1024 / 1024 / 1024).toFixed(2)} GB</td></tr>
                        <tr><td class="text-secondary">Boot Time</td><td class="font-monospace">${formatTime(data.boot_time)}</td></tr>
                    </tbody>
                </table>
            </div>
        `;
    } catch (error) {
        console.error('Error loading system status:', error);
    }
}

function updateResourceBar(type, percent) {
    document.getElementById(`${type}-usage`).textContent = `${percent.toFixed(1)}%`;
    const progress = document.getElementById(`${type}-progress`);
    progress.style.width = `${percent}%`;

    // Change color based on usage
    progress.className = 'progress-bar';
    if (percent > 90) progress.classList.add('bg-danger');
    else if (percent > 70) progress.classList.add('bg-warning');
    else progress.classList.add('bg-success');
}

// Load Updates
async function loadUpdates() {
    try {
        const response = await fetch('/api/updates/check');
        const data = await response.json();

        const content = document.getElementById('updates-content');
        content.innerHTML = `
            <div class="row g-4 mb-4">
                <div class="col-md-8">
                    <div class="glass-card p-4 h-100 border-start border-4 border-info">
                        <h5 class="mb-3 text-info"><i class="bi bi-info-circle me-2"></i>System Status</h5>
                        <div class="row g-3">
                            <div class="col-sm-6">
                                <div class="p-3 rounded bg-black bg-opacity-20">
                                    <small class="text-secondary text-uppercase text-xs">Package Manager</small>
                                    <div class="fw-bold font-monospace text-white">${data.package_manager}</div>
                                </div>
                            </div>
                            <div class="col-sm-6">
                                <div class="p-3 rounded bg-black bg-opacity-20">
                                    <small class="text-secondary text-uppercase text-xs">Total Updates</small>
                                    <div class="fw-bold fs-5 text-white">${data.updates_available || 0}</div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="col-md-4">
                     <div class="glass-card p-4 h-100 d-flex flex-column justify-content-center align-items-center text-center">
                        <div class="position-relative mb-3">
                            <i class="bi bi-shield-check display-4 ${data.security_updates > 0 ? 'text-warning' : 'text-success'}"></i>
                            ${data.security_updates > 0 ? `
                                <span class="position-absolute top-0 start-100 translate-middle badge rounded-pill bg-danger">
                                    ${data.security_updates}
                                    <span class="visually-hidden">security updates</span>
                                </span>
                            ` : ''}
                        </div>
                        <h6 class="mb-1">Security Patches</h6>
                        <p class="text-secondary text-sm mb-0">${data.security_updates || 0} critical updates pending</p>
                    </div>
                </div>
            </div>
            
            ${data.packages && data.packages.length > 0 ? `
                <div class="glass-card p-0 overflow-hidden">
                    <div class="p-3 border-bottom border-white border-opacity-10 d-flex justify-content-between align-items-center bg-black bg-opacity-20">
                        <h6 class="mb-0 text-white"><i class="bi bi-box-seam me-2"></i>Available Packages</h6>
                        <span class="badge bg-primary bg-opacity-20 text-primary">${data.packages.length}</span>
                    </div>
                    <div class="bg-black bg-opacity-50" style="max-height: 400px; overflow-y: auto;">
                        ${data.packages.map(pkg => `
                            <div class="px-4 py-3 border-bottom border-white border-opacity-5 flex justify-between items-center hover:bg-white hover:bg-opacity-05 transition-colors">
                                <code class="text-info">${escapeHtml(pkg)}</code>
                                <span class="badge bg-secondary bg-opacity-20 text-secondary text-xs">update</span>
                            </div>
                        `).join('')}
                    </div>
                    <div class="p-3 bg-black bg-opacity-20 text-end border-top border-white border-opacity-10">
                        <button class="btn btn-primary shadow-lg" onclick="applyUpdates()">
                            <i class="bi bi-cloud-download me-2"></i> Apply All Updates
                        </button>
                    </div>
                </div>
            ` : `
                <div class="glass-card p-5 text-center">
                    <div class="mb-3 text-success">
                        <i class="bi bi-check-circle-fill display-1 opacity-50"></i>
                    </div>
                    <h3 class="text-white">All Systems Operational</h3>
                    <p class="text-secondary">No updates currently available. Your system is up to date.</p>
                </div>
            `}
        `;
    } catch (error) {
        console.error('Error loading updates:', error);
    }
}

// Load Agents
async function loadAgents() {
    try {
        const response = await fetch('/api/agents/status');
        const data = await response.json();

        const content = document.getElementById('agents-content');
        content.innerHTML = `
            <div class="row g-4">
                ${data.agents.map(agent => `
                    <div class="col-md-4">
                        <div class="glass-card p-4 h-100 position-relative overflow-hidden group">
                            <div class="position-absolute top-0 end-0 p-3 opacity-10">
                                <i class="bi bi-robot display-4 text-primary"></i>
                            </div>
                            <div class="d-flex justify-content-between align-items-start mb-3">
                                <h6 class="mb-0 fw-bold">${agent.name}</h6>
                                <span class="badge ${agent.status === 'running' ? 'bg-success bg-opacity-10 text-success border border-success border-opacity-25' : 'bg-secondary bg-opacity-10 text-secondary'} rounded-pill">
                                    <i class="bi bi-circle-fill" style="font-size: 6px;"></i> ${agent.status}
                                </span>
                            </div>
                            <p class="text-secondary small mb-3" style="min-height: 2.5em;">${agent.description}</p>
                            <div class="mt-auto pt-3 border-top border-white border-opacity-10">
                                <div class="d-flex justify-content-between align-items-center text-xs text-secondary-light">
                                    <span>Processed</span>
                                    <span class="font-monospace text-primary bg-primary bg-opacity-10 px-2 py-1 rounded">${agent.messages_processed || 0} msgs</span>
                                </div>
                            </div>
                        </div>
                    </div>
                `).join('')
            }
            </div>
            `;
    } catch (error) {
        console.error('Error loading agents:', error);
    }
}

// Generate Report
async function generateReport() {
    // Fix: reportType is a name for radio group, not an ID. Use querySelector to get checked one.
    const reportType = document.querySelector('input[name="reportType"]:checked').value;
    const format = document.querySelector('input[name="format"]:checked').value;
    const includeAI = document.getElementById('includeAI').checked;

    try {
        const response = await fetch('/api/reports/generate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ report_type: reportType, format, include_ai: includeAI })
        });

        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `projectlibra_${reportType}_${Date.now()}.${format}`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);

        bootstrap.Modal.getInstance(document.getElementById('reportModal')).hide();
    } catch (error) {
        console.error('Error generating report:', error);
        alert('Failed to generate report');
    }
}

// Toggle Expert Mode
function toggleExpertMode() {
    expertMode = !expertMode;
    const btn = document.getElementById('expertModeBtn');

    if (expertMode) {
        btn.classList.add('btn-warning');
        btn.classList.remove('btn-outline-light');
        btn.innerHTML = '<i class="bi bi-person-badge-fill"></i> Expert Mode: ON';
    } else {
        btn.classList.remove('btn-warning');
        btn.classList.add('btn-outline-light');
        btn.innerHTML = '<i class="bi bi-person-badge"></i> Expert Mode';
    }
}

// Real-time Updates
function startRealTimeUpdates() {
    updateInterval = setInterval(() => {
        const activeSection = document.querySelector('.nav-link.active')?.getAttribute('data-section');
        if (activeSection === 'dashboard') {
            loadDashboardData();
        } else if (activeSection === 'system') {
            loadSystemStatus();
        }
    }, 5000); // Update every 5 seconds
}

// Filter Logs
function filterLogs() {
    const filter = document.getElementById('logFilter').value.toLowerCase();
    document.querySelectorAll('.log-entry').forEach(entry => {
        const text = entry.textContent.toLowerCase();
        entry.style.display = text.includes(filter) ? 'block' : 'none';
    });
}

// Clear Logs
function clearLogs() {
    document.getElementById('logs-content').innerHTML = '<p class="text-secondary">No logs available</p>';
}

// Utility Functions
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function formatTime(timestamp) {
    if (!timestamp) return 'N/A';
    const date = new Date(timestamp);
    return date.toLocaleString();
}

function getSeverityColor(severity) {
    const colors = {
        'low': 'success',
        'medium': 'warning',
        'high': 'danger',
        'critical': 'danger'
    };
    return colors[severity] || 'secondary';
}

function applyUpdates() {
    if (confirm('This will apply all security updates. Continue?')) {
        fetch('/api/updates/apply', { method: 'POST' })
            .then(() => alert('Updates applied successfully'))
            .catch(err => alert('Failed to apply updates'));
    }
}

function viewThreatDetails(id) {
    fetch(`/api/threats/${id}`)
        .then(r => r.json())
        .then(data => {
            alert(`Threat Details:\n${JSON.stringify(data, null, 2)}`);
        });
}

// AI-Powered Log Analysis
async function analyzeLogsWithAI() {
    const btn = document.getElementById('aiAnalyzeBtn');
    const resultsDiv = document.getElementById('ai-analysis-results');
    const anomaliesDiv = document.getElementById('ml-anomalies');

    try {
        // Show loading state
        btn.disabled = true;
        btn.innerHTML = '<i class="bi bi-hourglass-split"></i> Analyzing with AI...';

        // Get all logs from the display - extract from data-log attributes
        const logEntries = document.querySelectorAll('#logs-content .log-entry[data-log]');
        let logText = '';

        logEntries.forEach(entry => {
            try {
                const logData = JSON.parse(entry.getAttribute('data-log'));
                // Format: timestamp source [level] message
                const timestamp = new Date(logData.timestamp).toISOString();
                logText += `${timestamp} ${logData.source} [${logData.level.toUpperCase()}] ${logData.message}\n`;
            } catch (e) {
                console.error('Failed to parse log entry:', e);
            }
        });

        if (!logText.trim()) {
            // Fallback: try to get text content
            logText = document.getElementById('logs-content').innerText;
        }

        if (!logText.trim() || logText === 'No logs available') {
            resultsDiv.style.display = 'block';
            resultsDiv.innerHTML = `
            <div class="alert alert-warning">
                <i class="bi bi-info-circle"></i> No logs available for analysis. Please wait for logs to load or refresh the page.
            </div>
            `;
            btn.disabled = false;
            btn.innerHTML = '<i class="bi bi-robot"></i> Analyze with AI';
            return;
        }

        // Call API
        const response = await fetch('/api/logs/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ log_text: logText })
        });

        if (!response.ok) {
            throw new Error(`Analysis failed: ${response.statusText}`);
        }

        const data = await response.json();

        // Parse Markdown for AI analysis
        // Check if marked is available, otherwise fallback
        let aiAnalysisHtml = '';
        if (typeof marked !== 'undefined') {
            aiAnalysisHtml = marked.parse(data.ai_analysis || 'No AI insights available');
        } else {
            aiAnalysisHtml = `<pre style="white-space: pre-wrap;">${data.ai_analysis || 'No AI insights available'}</pre>`;
        }

        // Display AI Analysis Results
        resultsDiv.style.display = 'block';
        resultsDiv.innerHTML = `
            <div class="card glass-card mb-4">
                <div class="card-header bg-gradient-primary text-white d-flex justify-content-between align-items-center">
                    <h5 class="mb-0"><i class="bi bi-robot me-2"></i> AI Security Analysis</h5>
                    <span class="badge bg-light text-primary">${data.model || 'ProjectLibra AI'}</span>
                </div>
                <div class="card-body">
                    <!-- Statistics Summary -->
                    <div class="row g-2 mb-4">
                        <div class="col-md-2 col-4">
                            <div class="p-2 rounded bg-dark border border-secondary text-center">
                                <small class="text-muted d-block">Total</small>
                                <span class="h5 text-white mb-0">${data.analysis.total_entries || 0}</span>
                            </div>
                        </div>
                        <div class="col-md-2 col-4">
                            <div class="p-2 rounded bg-dark border border-danger text-center">
                                <small class="text-danger d-block">Critical</small>
                                <span class="h5 text-danger mb-0">${data.analysis.critical_count || 0}</span>
                            </div>
                        </div>
                        <div class="col-md-2 col-4">
                            <div class="p-2 rounded bg-dark border border-warning text-center">
                                <small class="text-warning d-block">Warning</small>
                                <span class="h5 text-warning mb-0">${data.analysis.warning_count || 0}</span>
                            </div>
                        </div>
                        <div class="col-md-2 col-4">
                            <div class="p-2 rounded bg-dark border border-info text-center">
                                <small class="text-info d-block">Sources</small>
                                <span class="h5 text-white mb-0">${data.analysis.unique_sources || 0}</span>
                            </div>
                        </div>
                    </div>

                    <!-- AI Insights (Markdown Rendered) -->
                    <h6 class="text-info mb-3"><i class="bi bi-stars"></i> Intelligence Report</h6>
                    <div class="markdown-body p-3 rounded bg-black bg-opacity-25 border border-white border-opacity-10 text-light">
                        ${aiAnalysisHtml}
                    </div>
                </div>
            </div>

            ${data.analysis.security_events && data.analysis.security_events.length > 0 ? `
            <div class="card glass-card mb-4">
                <div class="card-header bg-danger bg-opacity-25 text-white">
                    <h6 class="mb-0"><i class="bi bi-shield-exclamation me-2"></i> Security Events Detected</h6>
                </div>
                <ul class="list-group list-group-flush">
                    ${data.analysis.security_events.map(evt => `
                        <li class="list-group-item bg-transparent text-white border-bottom border-white border-opacity-10">
                            <div class="d-flex w-100 justify-content-between">
                                <h6 class="mb-1 text-danger">${evt.pattern || 'Security Event'}</h6>
                                <small class="text-muted">${evt.timestamp || ''}</small>
                            </div>
                            <p class="mb-1 small">${evt.message}</p>
                        </li>
                    `).join('')}
                </ul>
            </div>
            ` : ''}
            `;

        // Display ML Anomalies
        if (data.anomalies && data.anomalies.length > 0) {
            anomaliesDiv.style.display = 'block';
            anomaliesDiv.innerHTML = `
            < div class="card bg-dark border-danger" >
                    <div class="card-header bg-danger">
                        <i class="bi bi-exclamation-triangle"></i> ML Detected Anomalies (${data.anomalies.length})
                    </div>
                    <div class="card-body">
                        <div class="table-responsive">
                            <table class="table table-dark table-sm">
                                <thead>
                                    <tr>
                                        <th>Timestamp</th>
                                        <th>Source</th>
                                        <th>Message</th>
                                        <th>Anomaly Score</th>
                                        <th>Deviation</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    ${data.anomalies.slice(0, 20).map(anomaly => `
                                        <tr>
                                            <td><small>${anomaly.timestamp}</small></td>
                                            <td><span class="badge bg-secondary">${anomaly.source}</span></td>
                                            <td style="max-width: 300px; overflow: hidden; text-overflow: ellipsis;">
                                                ${anomaly.message.substring(0, 80)}...
                                            </td>
                                            <td>
                                                <span class="badge ${anomaly.anomaly_score > 0.8 ? 'bg-danger' : 'bg-warning'}">
                                                    ${anomaly.anomaly_score.toFixed(3)}
                                                </span>
                                            </td>
                                            <td>
                                                ${anomaly.deviation_details ? `
                                                    <small class="text-warning">
                                                        ${Object.entries(anomaly.deviation_details).map(([k, v]) =>
                `${k}: ${v.toFixed(2)}`
            ).join(', ')}
                                                    </small>
                                                ` : 'N/A'}
                                            </td>
                                        </tr>
                                    `).join('')}
                                </tbody>
                            </table>
                        </div>
                        <p class="text-muted mt-2">
                            <small><i class="bi bi-info-circle"></i> Showing top 20 anomalies. Higher scores indicate greater deviation from learned baseline behavior.</small>
                        </p>
                    </div>
                </div >
            `;
        } else {
            anomaliesDiv.style.display = 'block';
            anomaliesDiv.innerHTML = `
            < div class="alert alert-success" >
                <i class="bi bi-check-circle"></i> No significant anomalies detected.System behavior is within normal parameters.
                </div >
            `;
        }

    } catch (error) {
        console.error('AI Analysis Error:', error);
        resultsDiv.style.display = 'block';
        resultsDiv.innerHTML = `
            < div class="alert alert-danger" >
                <i class="bi bi-exclamation-triangle"></i> Analysis failed: ${error.message}
            </div >
            `;
    } finally {
        // Restore button
        btn.disabled = false;
        btn.innerHTML = '<i class="bi bi-robot"></i> Analyze with AI';
    }
}

// ML Status Display
async function showMLStatus() {
    const btn = document.getElementById('mlStatusBtn');

    try {
        btn.disabled = true;
        btn.innerHTML = '<i class="bi bi-hourglass-split"></i> Loading...';

        const response = await fetch('/api/ml/status');
        if (!response.ok) {
            throw new Error(`Failed to fetch ML status: ${response.statusText} `);
        }

        const data = await response.json();

        // Format thresholds section
        const thresholds = data.thresholds || {};
        const autoAdj = data.auto_adjustment || {};

        // Create modal-like overlay
        const modalHTML = `
            <div id="mlStatusModal" style="position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0, 0, 0, 0.92); z-index: 9999; display: flex; align-items: center; justify-content: center;">
                <div class="card" style="background: #181c24; border: 2px solid #17a2b8; width: 98%; max-width: 950px; max-height: 95vh; overflow-y: auto;">
                    <div class="card-header" style="background: #00d2ff; color: #181c24; border-bottom: 2px solid #17a2b8; display: flex; justify-content: space-between; align-items: center;">
                        <h5 class="mb-0 fw-bold">
                            <i class="bi bi-cpu"></i> Machine Learning Status
                        </h5>
                        <button class="btn btn-sm btn-dark" onclick="document.getElementById('mlStatusModal').remove()">
                            <i class="bi bi-x-lg"></i>
                        </button>
                    </div>
                    <div class="card-body">
                        <!-- Active Models -->
                        <h6 class="text-info"><i class="bi bi-diagram-3"></i> Active ML Models (${data.models.length})</h6>
                        <div class="row mb-4">
                            ${data.models.map(model => `
                                <div class="col-md-4 mb-3">
                                    <div class="card bg-secondary h-100">
                                        <div class="card-body">
                                            <h6 class="card-title text-white">${model.name}</h6>
                                            <p class="card-text small mb-1 text-white-50">
                                                <strong class="text-white">Type:</strong> ${model.type}
                                            </p>
                                            <p class="card-text small mb-1 text-white-50">
                                                <strong class="text-white">Status:</strong> <span class="badge bg-success">${model.status}</span>
                                            </p>
                                            ${model.trained_samples !== undefined ? `<p class="card-text small mb-0 text-white-50"><strong class="text-white">Samples:</strong> ${model.trained_samples}</p>` : ''}
                                            ${model.learning_rate !== undefined ? `<p class="card-text small mb-0 text-white-50"><strong class="text-white">Learning Rate:</strong> ${model.learning_rate}</p>` : ''}
                                            ${model.patterns !== undefined ? `<p class="card-text small mb-0 text-white-50"><strong class="text-white">Patterns:</strong> ${model.patterns}</p>` : ''}
                                        </div>
                                    </div>
                                </div>
                            `).join('')}
                        </div>
                        
                        <!-- Current Thresholds -->
                        <h6 style="color: #ffc107; font-weight: bold;"><i class="bi bi-sliders"></i> Current Thresholds</h6>
                        <div class="row mb-4">
                            <div class="col-md-3 mb-2">
                                <div class="card" style="background: #111; border: 2px solid #ffc107;">
                                    <div class="card-body text-center py-2">
                                        <h3 style="color: #fff; font-weight: bold;">${thresholds.anomaly_threshold || 0.65}</h3>
                                        <div style="color: #ffc107; font-weight: 500;">Anomaly Threshold</div>
                                    </div>
                                </div>
                            </div>
                            <div class="col-md-3 mb-2">
                                <div class="card" style="background: #111; border: 2px solid #ffc107;">
                                    <div class="card-body text-center py-2">
                                        <h3 style="color: #fff; font-weight: bold;">${thresholds.z_score_threshold || 3.0}</h3>
                                        <div style="color: #ffc107; font-weight: 500;">Z-Score Threshold</div>
                                    </div>
                                </div>
                            </div>
                            <div class="col-md-3 mb-2">
                                <div class="card" style="background: #111; border: 2px solid #17a2b8;">
                                    <div class="card-body text-center py-2">
                                        <h3 style="color: #fff; font-weight: bold;">${thresholds.current_samples || 0}</h3>
                                        <div style="color: #17a2b8; font-weight: 500;">Current Samples</div>
                                    </div>
                                </div>
                            </div>
                            <div class="col-md-3 mb-2">
                                <div class="card" style="background: #111; border: 2px solid #17a2b8;">
                                    <div class="card-body text-center py-2">
                                        <h3 style="color: #fff; font-weight: bold;">${thresholds.min_samples_for_stable || 100}</h3>
                                        <div style="color: #17a2b8; font-weight: 500;">Min Samples (Stable)</div>
                                    </div>
                                </div>
                            </div>
                        </div>
                        <!-- Auto Adjustment Schedule -->
                        <h6 style="color: #00e676; font-weight: bold;"><i class="bi bi-clock-history"></i> Auto-Adjustment Schedule</h6>
                        <div class="card mb-4" style="background: #111; border: 2px solid #00e676;">
                            <div class="card-body">
                                <div class="row">
                                    <div class="col-md-4">
                                        <div style="color: #00e676; font-weight: 600;">Interval:</div>
                                        <h4 style="color: #fff;">${autoAdj.interval_minutes || 30} minutes</h4>
                                    </div>
                                    <div class="col-md-4">
                                        <div style="color: #00e676; font-weight: 600;">Last Adjustment:</div>
                                        <h5 style="color: #fff;">${autoAdj.last_adjustment ? new Date(autoAdj.last_adjustment).toLocaleString() : 'Never'}</h5>
                                    </div>
                                    <div class="col-md-4">
                                        <div style="color: #00e676; font-weight: 600;">Next Adjustment:</div>
                                        <h4 style="color: #ffc107; font-weight: bold;">
                                            ${autoAdj.minutes_until_next > 0
                ? `${autoAdj.minutes_until_next} min`
                : 'Pending'}
                                        </h4>
                                        <div style="color: #aaa;">${autoAdj.next_adjustment || ''}</div>
                                    </div>
                                </div>
                            </div>
                        </div>
                        
                        <!-- Adaptive Learning Config -->
                        <h6 class="text-light"><i class="bi bi-gear"></i> Adaptive Learning Configuration</h6>
                        <ul class="list-group list-group-flush mb-3">
                            <li class="list-group-item bg-dark text-light border-secondary">
                                <i class="bi bi-check-circle text-success"></i> Online baseline learning enabled
                                <span class="float-end badge bg-success">Active</span>
                            </li>
                            <li class="list-group-item bg-dark text-light border-secondary">
                                <i class="bi bi-check-circle text-success"></i> Exponential moving average (EMA) for metric smoothing
                            </li>
                            <li class="list-group-item bg-dark text-light border-secondary">
                                <i class="bi bi-check-circle text-success"></i> Auto-threshold adjustment based on historical data
                            </li>
                            <li class="list-group-item bg-dark text-light border-secondary">
                                <i class="bi bi-check-circle text-success"></i> Multi-model ensemble detection
                            </li>
                        </ul>
                        
                        <!-- Features -->
                        <h6 class="text-light"><i class="bi bi-stars"></i> Features</h6>
                        <div class="d-flex flex-wrap gap-2 mb-3">
                            ${(data.features || []).map(feature => `
                                <span class="badge bg-primary">${feature}</span>
                            `).join('')}
                        </div>
                        
                        <div class="alert alert-info mb-0">
                            <i class="bi bi-info-circle"></i> ${data.adaptive_learning?.description || 'The system continuously learns from new data to improve anomaly detection accuracy. Baselines are updated automatically as system behavior evolves.'}
                        </div>
                    </div>
                    <div class="card-footer bg-dark border-info text-end">
                        <button class="btn btn-outline-info btn-sm" onclick="document.getElementById('mlStatusModal').remove()">
                            <i class="bi bi-x-circle"></i> Close
                        </button>
                    </div>
                </div >
            </div >
            `;

        document.body.insertAdjacentHTML('beforeend', modalHTML);

    } catch (error) {
        console.error('ML Status Error:', error);
        alert(`Failed to load ML status: ${error.message} `);
    } finally {
        btn.disabled = false;
        btn.innerHTML = '<i class="bi bi-bar-chart"></i> View ML Status';
    }
}
