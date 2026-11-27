(function (global) {
    const STORAGE_KEY = 'mirage_saved_sites_v1';

    function readSaved() {
        try {
            const raw = localStorage.getItem(STORAGE_KEY);
            const parsed = JSON.parse(raw || '[]');
            return Array.isArray(parsed) ? parsed : [];
        } catch {
            return [];
        }
    }

    function writeSaved(list) {
        try {
            localStorage.setItem(STORAGE_KEY, JSON.stringify(list.slice(0, 50)));
        } catch {}
    }

    function saveSite(site) {
        if (!site || !site.site_id || !site.target_url) return;
        const list = readSaved().filter((s) => s.site_id !== site.site_id);
        list.unshift({
            site_id: site.site_id,
            domain: site.domain || '',
            target_url: site.target_url,
            owner_name: site.owner_name || 'Customer',
            api_key: site.api_key || '',
            dashboard_key: site.dashboard_key || '',
        });
        writeSaved(list);
    }

    function saveMany(sites) {
        if (!Array.isArray(sites)) return;
        sites.forEach(saveSite);
    }

    function removeSite(siteId) {
        writeSaved(readSaved().filter((s) => s.site_id !== siteId));
    }

    async function restoreMissingSites(serverSites) {
        saveMany(serverSites || []);
        const saved = readSaved();
        if (!saved.length) return serverSites || [];

        const serverIds = new Set((serverSites || []).map((s) => s.site_id));
        const missing = saved.filter((s) => s.site_id && !serverIds.has(s.site_id));
        if (!missing.length) return serverSites || [];

        try {
            const res = await fetch('/api/sites/restore', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ sites: missing }),
            });
            const data = await res.json();
            if (res.ok && data.success && Array.isArray(data.sites)) {
                saveMany(data.sites);
                return data.sites;
            }
        } catch {}
        return serverSites || [];
    }

    function escapeHtml(val) {
        return String(val ?? '')
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
    }

    global.MirageSiteSync = {
        saveSite,
        saveMany,
        removeSite,
        getSavedSites: readSaved,
        restoreMissingSites,
        escapeHtml,
    };
})(window);
