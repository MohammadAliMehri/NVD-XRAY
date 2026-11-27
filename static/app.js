const form = document.querySelector('#research-form');
const queryInput = document.querySelector('#query');
const researchButton = document.querySelector('#research-button');
const formError = document.querySelector('#form-error');
const emptyState = document.querySelector('#empty-state');
const loadingState = document.querySelector('#loading-state');
const loadingTarget = document.querySelector('#loading-target');
const report = document.querySelector('#report');
const toast = document.querySelector('#toast');
let activeMode = 'cve';
let activeReport = null;
let activeReportId = null;

const historyKey = 'nvd-xray-recent';
const getHistory = () => {
    try {
        return JSON.parse(localStorage.getItem(historyKey) || '[]');
    } catch {
        return [];
    }
};

function setText(selector, value) {
    document.querySelector(selector).textContent = value;
}

async function loadReadiness() {
    const state = document.querySelector('#model-state');
    const dot = state.querySelector('.pulse-dot');
    try {
        const response = await fetch('/ready');
        const payload = await response.json();
        if (!response.ok || !payload.ready) throw new Error('Model unavailable');
        state.lastChild.textContent = `${payload.model} ready`;
        dot.className = 'pulse-dot';
    } catch {
        state.lastChild.textContent = 'Model offline';
        dot.className = 'pulse-dot offline';
    }
}

function setMode(mode) {
    activeMode = mode;
    document.querySelectorAll('.segment').forEach((button) => {
        button.classList.toggle('active', button.dataset.mode === mode);
    });
    queryInput.placeholder = mode === 'cve' ? 'CVE-2021-44228' : 'Apache Log4j remote code execution';
    queryInput.focus();
}

function showToast(message) {
    toast.textContent = message;
    toast.hidden = false;
    window.setTimeout(() => { toast.hidden = true; }, 2200);
}

function setBusy(busy, target = '') {
    researchButton.disabled = busy;
    researchButton.querySelector('span').textContent = busy ? 'Analyzing...' : 'Run research';
    emptyState.hidden = busy || Boolean(activeReport);
    report.hidden = busy || !activeReport;
    loadingState.hidden = !busy;
    if (busy) loadingTarget.textContent = target;
}

function addList(selector, items, fallback) {
    const container = document.querySelector(selector);
    container.replaceChildren();
    const values = items && items.length ? items : [fallback];
    values.forEach((value) => {
        const item = document.createElement('li');
        item.textContent = value;
        container.append(item);
    });
}

function renderMatches(matches) {
    const section = document.querySelector('#matches-section');
    const list = document.querySelector('#matches-list');
    list.replaceChildren();
    section.hidden = !matches.length;
    setText('#match-count', `${matches.length} records`);
    matches.forEach((match) => {
        const item = document.createElement('article');
        item.className = 'match-item';
        const head = document.createElement('div');
        head.className = 'match-item-head';
        const identifier = document.createElement('span');
        identifier.textContent = match.cve_id;
        const severity = document.createElement('span');
        severity.textContent = `${match.severity || 'UNKNOWN'}${match.cvss_score == null ? '' : ` · ${match.cvss_score}`}`;
        const summary = document.createElement('p');
        summary.textContent = match.summary;
        head.append(identifier, severity);
        item.append(head, summary);
        list.append(item);
    });
}

function renderProducts(products) {
    const list = document.querySelector('#products-list');
    list.replaceChildren();
    setText('#product-count', `${products.length} entries`);
    if (!products.length) {
        const empty = document.createElement('p');
        empty.className = 'reference-empty';
        empty.textContent = 'Affected product or version data is not available in the NVD result.';
        list.append(empty);
        return;
    }
    products.slice(0, 40).forEach((product) => {
        const item = document.createElement('article');
        item.className = 'product-item';
        const vendor = document.createElement('div');
        vendor.className = 'product-vendor';
        vendor.textContent = product.vendor;
        const name = document.createElement('div');
        name.className = 'product-name';
        name.textContent = product.product;
        const versions = document.createElement('div');
        versions.className = 'product-versions';
        versions.textContent = product.affected_versions.length
            ? product.affected_versions.join(', ')
            : 'Version applicability unknown';
        item.append(vendor, name, versions);
        list.append(item);
    });
}

function renderPocs(data) {
    const list = document.querySelector('#pocs-list');
    const section = document.querySelector('#poc-section');
    const indexLink = document.querySelector('#poc-index-link');
    list.replaceChildren();
    section.hidden = !data.cve_id;
    indexLink.hidden = !data.poc_index_url;
    if (data.poc_index_url) indexLink.href = data.poc_index_url;
    if (!data.public_pocs.length) {
        const empty = document.createElement('p');
        empty.className = 'reference-empty';
        empty.textContent = data.cve_id
            ? 'No public PoC metadata was returned by PoCIndex for this CVE.'
            : 'Public PoC lookup is available for exact CVE searches.';
        list.append(empty);
        return;
    }

    const count = document.createElement('div');
    count.className = 'poc-count';
    count.textContent = `${data.public_poc_count.toLocaleString()} indexed matches · showing ${data.public_pocs.length}`;
    list.append(count);
    data.public_pocs.forEach((poc) => {
        const link = document.createElement('a');
        link.className = 'poc-item';
        link.href = poc.url;
        link.target = '_blank';
        link.rel = 'noopener noreferrer';

        const title = document.createElement('div');
        title.className = 'poc-title';
        const sourceIcon = document.createElement('i');
        sourceIcon.dataset.lucide = 'github';
        const name = document.createElement('span');
        name.textContent = poc.name;
        const externalIcon = document.createElement('i');
        externalIcon.dataset.lucide = 'external-link';
        title.append(sourceIcon, name, externalIcon);

        const metadata = document.createElement('div');
        metadata.className = 'poc-metadata';
        const values = [poc.source];
        if (poc.stars != null) values.push(`${poc.stars.toLocaleString()} stars`);
        if (poc.pushed_at) values.push(`pushed ${poc.pushed_at}`);
        metadata.textContent = values.join(' · ');
        link.append(title, metadata);
        list.append(link);
    });
}

function renderReferences(references) {
    const list = document.querySelector('#references-list');
    list.replaceChildren();
    setText('#reference-count', `${references.length} sources`);
    if (!references.length) {
        const empty = document.createElement('p');
        empty.className = 'reference-empty';
        empty.textContent = 'No references were supplied.';
        list.append(empty);
        return;
    }
    references.forEach((reference) => {
        const link = document.createElement('a');
        link.className = 'reference-link';
        link.href = reference.url;
        link.target = '_blank';
        link.rel = 'noopener noreferrer';
        const label = document.createElement('span');
        label.textContent = reference.source ? `${reference.source} · ${reference.url}` : reference.url;
        const icon = document.createElement('i');
        icon.dataset.lucide = 'external-link';
        link.append(label, icon);
        list.append(link);
    });
}

function renderReport(data, reportId) {
    activeReport = data;
    activeReportId = reportId || null;
    const title = data.cve_id || 'Keyword research';
    setText('#report-title', title);
    setText('#report-summary', data.summary);
    setText('#report-impact', data.impact || 'Impact details were not supplied in the validated evidence.');
    setText('#report-attack-surface', data.attack_surface || 'Attack-surface details were not supplied in the validated evidence.');
    setText('#report-confidence', (data.confidence || 'medium').toUpperCase());
    setText('#report-published', data.published ? data.published.slice(0, 10) : 'Unknown');
    setText('#report-updated', data.last_modified ? data.last_modified.slice(0, 10) : 'Unknown');
    setText('#chat-context', title);
    document.querySelector('#chat-toggle').disabled = !activeReportId;
    const severity = (data.severity || 'UNKNOWN').toUpperCase();
    const badge = document.querySelector('#severity-badge');
    badge.textContent = severity;
    badge.className = `severity-badge ${severity.toLowerCase()}`;
    setText('#score-badge', `CVSS ${data.cvss_score == null ? 'Unknown' : data.cvss_score}`);
    renderMatches(data.search_results || []);
    renderProducts(data.affected_products || []);
    if (data.affected_product_total > data.affected_products.length) {
        setText('#product-count', `${data.affected_products.length} shown · ${data.affected_product_total} total`);
    }
    if (data.reference_total > data.references.length) {
        setText('#reference-count', `${data.references.length} shown · ${data.reference_total} total`);
    }
    addList('#remediation-list', data.remediation, 'No NVD-confirmed remediation was supplied.');
    addList('#recommendations-list', data.security_recommendations, 'No additional defensive guidance was supplied.');
    addList('#limitations-list', data.limitations, 'No report limitations were identified.');
    renderPocs(data);
    renderReferences(data.references || []);
    emptyState.hidden = true;
    loadingState.hidden = true;
    report.hidden = false;
    if (window.lucide) window.lucide.createIcons();
}

function renderHistory() {
    const list = document.querySelector('#recent-list');
    const history = getHistory();
    list.replaceChildren();
    if (!history.length) {
        const empty = document.createElement('p');
        empty.className = 'empty-history';
        empty.textContent = 'No recent research';
        list.append(empty);
        return;
    }
    history.forEach((value) => {
        const button = document.createElement('button');
        button.type = 'button';
        button.className = 'recent-item';
        button.textContent = value;
        const icon = document.createElement('i');
        icon.dataset.lucide = 'arrow-up-right';
        button.append(icon);
        button.addEventListener('click', () => {
            queryInput.value = value;
            setMode(/^CVE-/i.test(value) ? 'cve' : 'keyword');
            runResearch(value);
        });
        list.append(button);
    });
    if (window.lucide) window.lucide.createIcons();
}

function saveHistory(query) {
    const history = getHistory().filter((item) => item.toLowerCase() !== query.toLowerCase());
    localStorage.setItem(historyKey, JSON.stringify([query, ...history].slice(0, 6)));
    renderHistory();
}

async function runResearch(query) {
    formError.hidden = true;
    setBusy(true, query);
    try {
        const response = await fetch('/api/research', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ query }),
        });
        const payload = await response.json();
        if (!response.ok) throw new Error(payload.error || 'Research failed.');
        renderReport(payload.report, payload.report_id);
        saveHistory(query);
    } catch (error) {
        formError.textContent = error.message;
        formError.hidden = false;
        activeReport ? (report.hidden = false) : (emptyState.hidden = false);
    } finally {
        setBusy(false);
    }
}

form.addEventListener('submit', (event) => {
    event.preventDefault();
    const query = queryInput.value.trim();
    if (activeMode === 'cve' && !/^CVE-\d{4}-\d{4,}$/i.test(query)) {
        formError.textContent = 'Enter a valid CVE ID, for example CVE-2021-44228.';
        formError.hidden = false;
        queryInput.focus();
        return;
    }
    runResearch(query);
});

function appendChatMessage(text, role) {
    const messages = document.querySelector('#chat-messages');
    const message = document.createElement('div');
    message.className = `chat-message ${role === 'user' ? 'user-message' : 'assistant-message'}`;
    message.textContent = text;
    messages.append(message);
    messages.scrollTop = messages.scrollHeight;
}

function setChatOpen(open) {
    document.querySelector('#chat-panel').hidden = !open;
    document.querySelector('#chat-toggle').hidden = open;
    if (open) document.querySelector('#chat-question').focus();
}

document.querySelector('#chat-toggle').addEventListener('click', () => setChatOpen(true));
document.querySelector('#chat-close').addEventListener('click', () => setChatOpen(false));
document.querySelector('#chat-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    if (!activeReportId) return;
    const input = document.querySelector('#chat-question');
    const sendButton = event.currentTarget.querySelector('button');
    const question = input.value.trim();
    if (!question) return;
    appendChatMessage(question, 'user');
    input.value = '';
    input.disabled = true;
    sendButton.disabled = true;
    appendChatMessage('Reading the validated report...', 'assistant');
    const pendingMessage = document.querySelector('#chat-messages').lastElementChild;
    try {
        const response = await fetch('/api/chat', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ report_id: activeReportId, question }),
        });
        const payload = await response.json();
        if (!response.ok) throw new Error(payload.error || 'Unable to answer this question.');
        pendingMessage.textContent = payload.answer;
    } catch (error) {
        pendingMessage.textContent = error.message;
        pendingMessage.classList.add('chat-error');
    } finally {
        input.disabled = false;
        sendButton.disabled = false;
        input.focus();
        document.querySelector('#chat-messages').scrollTop = document.querySelector('#chat-messages').scrollHeight;
    }
});

document.querySelectorAll('.segment').forEach((button) => {
    button.addEventListener('click', () => setMode(button.dataset.mode));
});

document.querySelector('#sample-query').addEventListener('click', () => {
    queryInput.value = 'CVE-2021-44228';
    setMode('cve');
    runResearch(queryInput.value);
});

document.querySelector('#clear-history').addEventListener('click', () => {
    localStorage.removeItem(historyKey);
    renderHistory();
});

document.querySelector('#copy-report').addEventListener('click', async () => {
    if (!activeReport) return;
    await navigator.clipboard.writeText(`${activeReport.cve_id || 'NVD Keyword Research'}\n\n${activeReport.summary}`);
    showToast('Summary copied');
});

document.querySelector('#download-report').addEventListener('click', () => {
    if (!activeReport) return;
    const blob = new Blob([JSON.stringify(activeReport, null, 2)], { type: 'application/json' });
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = `${(activeReport.cve_id || 'nvd-xray-report').replace(/[^a-z0-9-]/gi, '-')}.json`;
    link.click();
    URL.revokeObjectURL(link.href);
    showToast('JSON exported');
});

renderHistory();
loadReadiness();
if (window.lucide) window.lucide.createIcons();
