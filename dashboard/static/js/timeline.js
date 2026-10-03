function renderTimeline(events, container) {
    // Placeholder demo data since backend is simple
    const demoEvents = [
        { time: '11:02:03', action: 'HTTP scan on /robots.txt', pts: '+5', score: '5', icon: '🌐', level: 'low' },
        { time: '11:02:08', action: 'HTTP login attempt (admin)', pts: '+8', score: '13', icon: '🔑', level: 'med' },
        { time: '11:02:12', action: 'HTTP GET /.env', pts: '+20', score: '33', icon: '🌐', level: 'high' },
        { time: '11:03:50', action: 'SHELL ACCESS - ran: whoami', pts: '+20', score: '53', icon: '💻', level: 'critical' },
        { time: '11:03:52', action: 'AUTO-QUARANTINE TRIGGERED', pts: '', score: '94', icon: '🔴', level: 'critical' }
    ];

    let html = '<div style="font-family: monospace; line-height: 1.6;">';
    html += '<p>━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━</p>';
    
    demoEvents.forEach(ev => {
        let color = '#c9d1d9';
        if(ev.level === 'high') color = 'var(--neon-orange)';
        if(ev.level === 'critical') color = 'var(--neon-red)';
        if(ev.level === 'med') color = 'var(--neon-yellow)';

        html += `<div style="display:flex; justify-content:space-between; color: ${color};">
            <span>${ev.time} ${ev.icon} ${ev.action}</span>
            <span>[${ev.pts} → Score: ${ev.score}]</span>
        </div>`;
    });

    html += '<p>━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━</p>';
    html += '<p>Final Score: 94/100 | Class: CRITICAL</p>';
    html += '</div>';

    container.innerHTML = html;
}
