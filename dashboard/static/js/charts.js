/**
 * MIRAGE Junior — Dashboard Charts & Live Data
 * Uses Chart.js for visualizations, auto-refreshes every 5 seconds via /api/stats
 */

let threatDistChart, topCountriesChart, attackTimelineChart, mitreChart;

function initCharts() {
    // Global Chart.js dark theme
    Chart.defaults.color = '#8b949e';
    Chart.defaults.borderColor = '#30363d';
    Chart.defaults.font.family = "'Segoe UI', Tahoma, Geneva, Verdana, sans-serif";

    // ─── Threat Distribution (Doughnut) ───────────────────────────────
    const ctxThreat = document.getElementById('threatDistChart');
    if (ctxThreat) {
        threatDistChart = new Chart(ctxThreat, {
            type: 'doughnut',
            data: {
                labels: ['🟢 Scanner', '🟡 Suspicious', '🟠 Active Threat', '🔴 Critical'],
                datasets: [{
                    data: [0, 0, 0, 0],
                    backgroundColor: ['#00ff41', '#ffcc00', '#ff8c00', '#ff4444'],
                    borderWidth: 2,
                    borderColor: '#161b22',
                    hoverOffset: 8
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: { padding: 15, usePointStyle: true, pointStyle: 'circle' }
                    }
                },
                cutout: '65%'
            }
        });
    }

    // ─── Top Attacking Countries (Bar) ────────────────────────────────
    const ctxCountry = document.getElementById('topCountriesChart');
    if (ctxCountry) {
        topCountriesChart = new Chart(ctxCountry, {
            type: 'bar',
            data: {
                labels: [],
                datasets: [{
                    label: 'Attack Count',
                    data: [],
                    backgroundColor: ['#ff4444', '#ff8c00', '#ffcc00', '#58a6ff', '#bc8cff'],
                    borderRadius: 4,
                    borderSkipped: false
                }]
            },
            options: {
                responsive: true,
                plugins: { legend: { display: false } },
                scales: {
                    y: { beginAtZero: true, grid: { color: '#21262d' } },
                    x: { grid: { display: false } }
                }
            }
        });
    }

    // ─── Attack Timeline — Last 24h (Bar) ─────────────────────────────
    const ctxTimeline = document.getElementById('attackTimelineChart');
    if (ctxTimeline) {
        attackTimelineChart = new Chart(ctxTimeline, {
            type: 'bar',
            data: {
                labels: Array.from({length: 24}, (_, i) => `${String(i).padStart(2, '0')}:00`),
                datasets: [{
                    label: 'Attacks',
                    data: Array(24).fill(0),
                    backgroundColor: 'rgba(188, 140, 255, 0.6)',
                    borderColor: '#bc8cff',
                    borderWidth: 1,
                    borderRadius: 3
                }]
            },
            options: {
                responsive: true,
                plugins: { legend: { display: false } },
                scales: {
                    y: { beginAtZero: true, grid: { color: '#21262d' } },
                    x: { grid: { display: false } }
                }
            }
        });
    }

    // ─── MITRE ATT&CK Heatmap (Horizontal Bar) ───────────────────────
    const ctxMitre = document.getElementById('mitreChart');
    if (ctxMitre) {
        mitreChart = new Chart(ctxMitre, {
            type: 'bar',
            data: {
                labels: [],
                datasets: [{
                    label: 'Detections',
                    data: [],
                    backgroundColor: 'rgba(255, 68, 68, 0.7)',
                    borderColor: '#ff4444',
                    borderWidth: 1,
                    borderRadius: 3
                }]
            },
            options: {
                indexAxis: 'y',
                responsive: true,
                plugins: { legend: { display: false } },
                scales: {
                    x: { beginAtZero: true, grid: { color: '#21262d' } },
                    y: { grid: { display: false } }
                }
            }
        });
    }

    // Initial fetch + auto-refresh
    fetchStats();
    fetchLiveEvents();
    setInterval(fetchStats, 5000);
    setInterval(fetchLiveEvents, 5000);
}

function fetchStats() {
    fetch('/api/stats')
        .then(res => res.json())
        .then(data => {
            // Update stat cards with animation
            animateValue('stat-total-hits', data.total_hits);
            animateValue('stat-unique-ips', data.unique_ips);
            animateValue('stat-creds', data.creds_captured);
            animateValue('stat-avg-score', data.avg_threat_score);
            animateValue('stat-quarantined', data.ips_quarantined);

            // Update charts
            if (threatDistChart) {
                const dist = data.threat_distribution;
                threatDistChart.data.datasets[0].data = [
                    dist.Scanner || 0, dist.Suspicious || 0,
                    dist.Active || 0, dist.Critical || 0
                ];
                threatDistChart.update('none');
            }

            if (topCountriesChart && data.top_countries) {
                topCountriesChart.data.labels = Object.keys(data.top_countries);
                topCountriesChart.data.datasets[0].data = Object.values(data.top_countries);
                topCountriesChart.update('none');
            }

            if (attackTimelineChart && data.hourly_timeline) {
                const hourlyData = Array(24).fill(0);
                data.hourly_timeline.forEach(h => {
                    const hour = parseInt(h.hour);
                    if (!isNaN(hour)) hourlyData[hour] = h.count;
                });
                attackTimelineChart.data.datasets[0].data = hourlyData;
                attackTimelineChart.update('none');
            }

            if (mitreChart && data.mitre_stats) {
                mitreChart.data.labels = Object.keys(data.mitre_stats);
                mitreChart.data.datasets[0].data = Object.values(data.mitre_stats);
                mitreChart.update('none');
            }
        })
        .catch(err => console.error("Stats fetch error:", err));
}

function fetchLiveEvents() {
    fetch('/api/events')
        .then(res => res.json())
        .then(data => {
            const tbody = document.querySelector('#live-attack-table tbody');
            if (!tbody || !data.events) return;

            tbody.innerHTML = '';
            data.events.forEach(evt => {
                const row = document.createElement('tr');
                const scoreClass = getScoreClass(evt.classification);
                const ts = evt.timestamp ? evt.timestamp.substring(11, 19) : '--:--:--';
                row.innerHTML = `
                    <td>${ts}</td>
                    <td><a href="/attacker/${evt.ip_address}" style="color: #58a6ff;">${evt.ip_address}</a></td>
                    <td>${evt.country || 'Unknown'}</td>
                    <td>${getEventIcon(evt.protocol)} ${evt.event_type}</td>
                    <td><span class="badge ${scoreClass}">${evt.classification || 'N/A'}</span></td>
                `;
                tbody.appendChild(row);
            });
        })
        .catch(err => console.error("Events fetch error:", err));
}

function getScoreClass(classification) {
    switch(classification) {
        case 'CRITICAL': return 'badge-critical';
        case 'ACTIVE_THREAT': return 'badge-active';
        case 'SUSPICIOUS': return 'badge-suspicious';
        case 'SCANNER': return 'badge-scanner';
        default: return 'badge-scanner';
    }
}

function getEventIcon(protocol) {
    switch(protocol) {
        case 'HTTP': return '🌐';
        case 'SSH': return '🖥️';
        case 'FTP': return '📁';
        case 'HONEYTOKEN': return '🪤';
        default: return '⚡';
    }
}

function animateValue(elementId, endVal) {
    const el = document.getElementById(elementId);
    if (!el) return;
    const current = parseInt(el.innerText) || 0;
    if (current === endVal) return;
    el.innerText = endVal;
    el.style.transform = 'scale(1.1)';
    setTimeout(() => { el.style.transform = 'scale(1)'; }, 200);
}
