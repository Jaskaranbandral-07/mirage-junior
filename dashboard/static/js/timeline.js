function getProtocolIcon(protocol) {
    switch ((protocol || '').toUpperCase()) {
        case 'HTTP': return '🌐';
        case 'SSH': return '🖥️';
        case 'FTP': return '📁';
        case 'HONEYTOKEN': return '🪤';
        default: return '⚡';
    }
}

function getDotColor(score) {
    if (score >= 76) return 'red';
    if (score >= 51) return 'orange';
    if (score >= 21) return 'yellow';
    return 'green';
}

function escapeHtml(text) {
    if (!text) return '';
    return String(text)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

function renderTimeline(events, container) {
    if (!container) return;

    if (!events || events.length === 0) {
        container.innerHTML = '<p style="color: var(--text-muted); padding: 20px 0; text-align: center;">No events recorded for this attacker.</p>';
        return;
    }

    let html = '<div class="timeline">';

    events.forEach(ev => {
        const score = ev.running_score !== undefined ? ev.running_score : (ev.threat_pts || 0);
        const dotColor = getDotColor(score);
        const icon = getProtocolIcon(ev.protocol);
        const pts = ev.threat_pts ? (ev.threat_pts > 0 ? `+${ev.threat_pts}` : `${ev.threat_pts}`) : '+0';
        const mitreTag = ev.mitre_id ? `<span class="tag mitre-tag">${escapeHtml(ev.mitre_id)}</span>` : '';
        const desc = ev.details || ev.event_type || 'Activity detected';

        html += `
            <div class="timeline-item">
                <span class="timeline-dot ${dotColor}"></span>
                <div class="timeline-content">
                    <div style="display: flex; justify-content: space-between; align-items: baseline; margin-bottom: 6px;">
                        <span class="timeline-time">${escapeHtml(ev.timestamp || '')}</span>
                        <span class="timeline-score" style="color: var(--neon-${dotColor});">${pts} pts &rarr; Score: ${score}</span>
                    </div>
                    <div style="font-size: 0.95rem; color: var(--text-bright); display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px;">
                        <span>${icon} [${escapeHtml(ev.protocol || 'EVENT')}] <strong>${escapeHtml(ev.event_type || '')}</strong>: ${escapeHtml(desc)}</span>
                        ${mitreTag}
                    </div>
                </div>
            </div>
        `;
    });

    html += '</div>';
    container.innerHTML = html;
}
