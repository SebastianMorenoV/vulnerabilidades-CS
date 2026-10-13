// =============================================================================
// SSRF INSPECTOR — SOBER DEVELOPER LOGIC
// Control de autenticación, ejecución HTTP, comparador y consola
// =============================================================================

document.addEventListener('DOMContentLoaded', () => {

  // 1. ESTADO DE AUTENTICACIÓN
  let currentUser = {
    username: 'alumno',
    password: 'password',
    role: 'ROLE_USER'
  };

  const BASE_URL = window.location.origin;

  // 2. ESCENARIOS PREDEFINIDOS
  const SCENARIOS = {
    'cloud-metadata': {
      title: 'Metadatos Cloud (AWS IMDS)',
      desc: 'Extracción de credenciales temporales de AWS IAM (AccessKeyId, SecretAccessKey, Token) a través del endpoint local del servicio de metadatos.',
      method: 'GET',
      targetUrl: `${BASE_URL}/latest/meta-data/iam/security-credentials`,
      isDirect: false
    },
    'intranet-keys-get': {
      title: 'Bóveda interna (GET)',
      desc: 'Consulta directa a la intranet de credenciales confidenciales (base de datos, Stripe, JWT) puenteando el perímetro de red.',
      method: 'GET',
      targetUrl: `${BASE_URL}/internal/admin/claves-api`,
      isDirect: false
    },
    'intranet-keys-post': {
      title: 'Bóveda interna (POST JSON)',
      desc: 'Inyección de URL objetivo en payload JSON ({ "url": "..." }) procesado por el endpoint /fetch-url.',
      method: 'POST',
      targetUrl: `${BASE_URL}/internal/admin/claves-api`,
      isDirect: false
    },
    'file-scheme': {
      title: 'Esquema file://',
      desc: 'Lectura de archivos arbitrarios del sistema operativo anfitrión sin protocolo HTTP (win.ini o /etc/passwd).',
      method: 'GET',
      targetUrl: 'file:///C:/Windows/win.ini',
      isDirect: false
    },
    'loopback-ip': {
      title: 'Loopback IP (127.0.0.1)',
      desc: 'Intento de evasión de reglas de dominio mediante notación numérica IPv4 de Loopback (127.0.0.1).',
      method: 'GET',
      targetUrl: `http://127.0.0.1:${window.location.port || '8080'}/internal/admin/claves-api`,
      isDirect: false
    },
    'legit-public': {
      title: 'Petición externa pública',
      desc: 'Consulta a API externa legítima en internet público para verificar que los filtros no bloquean tráfico de negocio válido.',
      method: 'GET',
      targetUrl: 'https://httpbin.org/get',
      isDirect: false
    },
    'direct-perimeter': {
      title: 'Acceso perimetral directo',
      desc: 'Comprobación de Spring Security: acceso directo sin SSRF con rol USER devuelve HTTP 403 Forbidden.',
      method: 'GET',
      targetUrl: `${BASE_URL}/internal/admin/claves-api`,
      isDirect: true
    }
  };

  let activeScenarioKey = 'cloud-metadata';
  const auditLogs = [];

  // ==========================================
  // ELEMENTOS DEL DOM
  // ==========================================
  const btnAuthAlumno = document.getElementById('btn-auth-alumno');
  const btnAuthAdmin = document.getElementById('btn-auth-admin');
  const badgeActiveRole = document.getElementById('badge-active-role');
  const consoleAuthPreview = document.getElementById('console-auth-preview');

  const navTabs = document.querySelectorAll('.nav-tab');
  const tabPanes = document.querySelectorAll('.tab-pane');

  const scenarioCards = document.querySelectorAll('.scenario-card');
  const currentScenarioTitle = document.getElementById('current-scenario-title');
  const currentScenarioDesc = document.getElementById('current-scenario-desc');
  const currentMethodTag = document.getElementById('current-method-tag');
  const currentTargetUrlInput = document.getElementById('current-target-url');
  const btnResetScenarioUrl = document.getElementById('btn-reset-scenario-url');
  const btnRunComparison = document.getElementById('btn-run-comparison');
  const btnRunVulnOnly = document.getElementById('btn-run-vuln-only');
  const btnRunSafeOnly = document.getElementById('btn-run-safe-only');

  const vulnStatusBadge = document.getElementById('vuln-status-badge');
  const vulnResponseTime = document.getElementById('vuln-response-time');
  const vulnHttpCode = document.getElementById('vuln-http-code');
  const vulnVerdictBox = document.getElementById('vuln-verdict-box');
  const vulnResponseBox = document.getElementById('vuln-response-box');
  const vulnEndpointPath = document.getElementById('vuln-endpoint-path');
  const btnCopyVuln = document.getElementById('btn-copy-vuln');

  const safeStatusBadge = document.getElementById('safe-status-badge');
  const safeResponseTime = document.getElementById('safe-response-time');
  const safeHttpCode = document.getElementById('safe-http-code');
  const safeVerdictBox = document.getElementById('safe-verdict-box');
  const safeResponseBox = document.getElementById('safe-response-box');
  const safeEndpointPath = document.getElementById('safe-endpoint-path');
  const btnCopySafe = document.getElementById('btn-copy-safe');

  const consoleEndpointType = document.getElementById('console-endpoint-type');
  const groupTargetUrl = document.getElementById('group-target-url');
  const consoleTargetUrl = document.getElementById('console-target-url');
  const groupFullUrl = document.getElementById('group-full-url');
  const consoleFullUrl = document.getElementById('console-full-url');
  const consoleMethod = document.getElementById('console-method');
  const groupJsonBody = document.getElementById('group-json-body');
  const consoleJsonBody = document.getElementById('console-json-body');
  const btnConsoleSend = document.getElementById('btn-console-send');
  const consoleStatusBadge = document.getElementById('console-status-badge');
  const consoleTimeStat = document.getElementById('console-time-stat');
  const consoleStatusStat = document.getElementById('console-status-stat');
  const consoleTypeStat = document.getElementById('console-type-stat');
  const consoleVerdictBox = document.getElementById('console-verdict-box');
  const consoleResponseBox = document.getElementById('console-response-box');
  const btnCopyConsole = document.getElementById('btn-copy-console');

  const auditTableBody = document.getElementById('audit-table-body');
  const btnClearHistory = document.getElementById('btn-clear-history');
  const toastEl = document.getElementById('toast-notification');

  // ==========================================
  // HELPERS
  // ==========================================
  function showToast(msg) {
    toastEl.textContent = msg;
    toastEl.classList.add('show');
    setTimeout(() => toastEl.classList.remove('show'), 2400);
  }

  function getAuthHeader() {
    const creds = `${currentUser.username}:${currentUser.password}`;
    return `Basic ${btoa(creds)}`;
  }

  function formatTime(ms) {
    return `${ms} ms`;
  }

  function formatResponseBody(data) {
    if (typeof data === 'object') {
      try {
        return JSON.stringify(data, null, 2);
      } catch (e) {
        return String(data);
      }
    }
    try {
      const parsed = JSON.parse(data);
      return JSON.stringify(parsed, null, 2);
    } catch (e) {
      return String(data);
    }
  }

  function updateAuthUI() {
    if (currentUser.username === 'admin') {
      btnAuthAdmin.classList.add('active', 'admin');
      btnAuthAlumno.classList.remove('active');
      badgeActiveRole.textContent = 'ROLE_ADMIN';
      badgeActiveRole.className = 'current-role-badge role-admin';
    } else {
      btnAuthAlumno.classList.add('active');
      btnAuthAdmin.classList.remove('active', 'admin');
      badgeActiveRole.textContent = 'ROLE_USER';
      badgeActiveRole.className = 'current-role-badge role-user';
    }

    const b64 = btoa(`${currentUser.username}:${currentUser.password}`);
    consoleAuthPreview.textContent = `Authorization: Basic ${b64} (${currentUser.username}:${currentUser.password})`;
  }

  // ==========================================
  // GESTIÓN DE AUTENTICACIÓN
  // ==========================================
  btnAuthAlumno.addEventListener('click', () => {
    currentUser = { username: 'alumno', password: 'password', role: 'ROLE_USER' };
    updateAuthUI();
    showToast('Usuario cambiado: alumno (ROLE_USER)');
  });

  btnAuthAdmin.addEventListener('click', () => {
    currentUser = { username: 'admin', password: 'password', role: 'ROLE_ADMIN' };
    updateAuthUI();
    showToast('Usuario cambiado: admin (ROLE_ADMIN)');
  });

  // ==========================================
  // NAVEGACIÓN POR TABS (Underline style)
  // ==========================================
  navTabs.forEach(tab => {
    tab.addEventListener('click', () => {
      navTabs.forEach(t => t.classList.remove('active'));
      tabPanes.forEach(p => p.classList.remove('active'));

      tab.classList.add('active');
      const targetId = tab.dataset.tab;
      document.getElementById(targetId).classList.add('active');
    });
  });

  // ==========================================
  // SELECCIÓN DE ESCENARIO
  // ==========================================
  function selectScenario(scenarioKey) {
    activeScenarioKey = scenarioKey;
    const scen = SCENARIOS[scenarioKey];
    if (!scen) return;

    scenarioCards.forEach(c => {
      if (c.dataset.scenario === scenarioKey) {
        c.classList.add('active');
      } else {
        c.classList.remove('active');
      }
    });

    currentScenarioTitle.textContent = scen.title;
    currentScenarioDesc.textContent = scen.desc;
    currentMethodTag.textContent = scen.method;
    currentTargetUrlInput.value = scen.targetUrl;

    if (scen.method === 'POST') {
      vulnEndpointPath.textContent = '/api/vulnerable/fetch-url';
      safeEndpointPath.textContent = '/api/mitigado/fetch-url';
    } else if (scen.isDirect) {
      vulnEndpointPath.textContent = '/internal/admin/claves-api';
      safeEndpointPath.textContent = '/internal/admin/claves-api';
    } else {
      vulnEndpointPath.textContent = '/api/vulnerable/preview';
      safeEndpointPath.textContent = '/api/mitigado/preview';
    }

    vulnStatusBadge.textContent = 'Sin ejecutar';
    vulnStatusBadge.className = 'status-badge status-empty';
    vulnVerdictBox.className = 'verdict-box neutral';
    vulnVerdictBox.innerHTML = `Listo para probar <strong>${scen.title}</strong> en endpoint vulnerable.`;
    vulnResponseBox.textContent = '// Respuesta no iniciada';
    vulnResponseTime.textContent = '-';
    vulnHttpCode.textContent = '-';

    safeStatusBadge.textContent = 'Sin ejecutar';
    safeStatusBadge.className = 'status-badge status-empty';
    safeVerdictBox.className = 'verdict-box neutral';
    safeVerdictBox.innerHTML = `Listo para probar <strong>${scen.title}</strong> en endpoint mitigado.`;
    safeResponseBox.textContent = '// Respuesta no iniciada';
    safeResponseTime.textContent = '-';
    safeHttpCode.textContent = '-';
  }

  scenarioCards.forEach(card => {
    card.addEventListener('click', () => {
      selectScenario(card.dataset.scenario);
    });
  });

  btnResetScenarioUrl.addEventListener('click', () => {
    const scen = SCENARIOS[activeScenarioKey];
    if (scen) {
      currentTargetUrlInput.value = scen.targetUrl;
      showToast('URL restablecida.');
    }
  });

  // ==========================================
  // MOTOR DE EJECUCIÓN HTTP CENTRAL
  // ==========================================
  async function doFetch(url, options = {}) {
    const start = performance.now();
    const headers = {
      'Authorization': getAuthHeader(),
      ...(options.headers || {})
    };

    try {
      const response = await fetch(url, { ...options, headers });
      const duration = Math.round(performance.now() - start);

      let data;
      const contentType = response.headers.get('content-type') || '';
      if (contentType.includes('application/json')) {
        data = await response.json();
      } else {
        data = await response.text();
      }

      return {
        ok: response.ok,
        status: response.status,
        statusText: response.statusText,
        duration,
        data,
        headers: response.headers
      };
    } catch (err) {
      const duration = Math.round(performance.now() - start);
      return {
        ok: false,
        status: 0,
        statusText: 'Connection Error',
        duration,
        data: { error: err.message || 'Error de conexión' },
        headers: null
      };
    }
  }

  // ==========================================
  // EJECUCIÓN EN COMPARADOR
  // ==========================================
  async function runVulnerableScenario() {
    const targetUrl = currentTargetUrlInput.value.trim();
    const scen = SCENARIOS[activeScenarioKey];

    vulnStatusBadge.innerHTML = '<span class="spinner"></span> Enviando';
    vulnStatusBadge.className = 'status-badge status-empty';
    vulnResponseBox.textContent = 'Esperando respuesta...';

    let requestUrl = '';
    let fetchOptions = {};

    if (scen.isDirect) {
      requestUrl = targetUrl;
      fetchOptions = { method: 'GET' };
    } else if (scen.method === 'POST') {
      requestUrl = `${BASE_URL}/api/vulnerable/fetch-url`;
      fetchOptions = {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: targetUrl })
      };
    } else {
      requestUrl = `${BASE_URL}/api/vulnerable/preview?url=${encodeURIComponent(targetUrl)}`;
      fetchOptions = { method: 'GET' };
    }

    const res = await doFetch(requestUrl, fetchOptions);

    vulnResponseTime.textContent = formatTime(res.duration);
    vulnHttpCode.textContent = res.status || 'ERR';
    vulnResponseBox.textContent = formatResponseBody(res.data);

    if (res.status === 200) {
      vulnStatusBadge.textContent = '200 OK';
      vulnStatusBadge.className = 'status-badge status-200';
      vulnVerdictBox.className = 'verdict-box vuln-fail';
      vulnVerdictBox.innerHTML = `
        <span class="status-dot dot-vuln"></span><strong>SSRF exitoso:</strong> El servidor procesó la petición interna y obtuvo los datos confidenciales sin validación.
      `;
    } else if (res.status === 403) {
      vulnStatusBadge.textContent = '403 Forbidden';
      vulnStatusBadge.className = 'status-badge status-403';
      vulnVerdictBox.className = 'verdict-box neutral';
      vulnVerdictBox.innerHTML = `
        <span class="status-dot dot-neutral"></span><strong>Acceso denegado:</strong> El usuario actual carece de privilegios directos.
      `;
    } else {
      vulnStatusBadge.textContent = `${res.status} Error`;
      vulnStatusBadge.className = 'status-badge status-400';
      vulnVerdictBox.className = 'verdict-box neutral';
      vulnVerdictBox.innerHTML = `
        <span class="status-dot dot-neutral"></span>Código HTTP ${res.status}.
      `;
    }

    recordAuditLog('Vulnerable', scen.method, targetUrl, res.status, res.status === 200 ? 'SSRF exitoso' : 'Denegado/Error');
  }

  async function runMitigatedScenario() {
    const targetUrl = currentTargetUrlInput.value.trim();
    const scen = SCENARIOS[activeScenarioKey];

    safeStatusBadge.innerHTML = '<span class="spinner"></span> Validando';
    safeStatusBadge.className = 'status-badge status-empty';
    safeResponseBox.textContent = 'Esperando respuesta...';

    let requestUrl = '';
    let fetchOptions = {};

    if (scen.isDirect) {
      requestUrl = targetUrl;
      fetchOptions = { method: 'GET' };
    } else if (scen.method === 'POST') {
      requestUrl = `${BASE_URL}/api/mitigado/fetch-url`;
      fetchOptions = {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: targetUrl })
      };
    } else {
      requestUrl = `${BASE_URL}/api/mitigado/preview?url=${encodeURIComponent(targetUrl)}`;
      fetchOptions = { method: 'GET' };
    }

    const res = await doFetch(requestUrl, fetchOptions);

    safeResponseTime.textContent = formatTime(res.duration);
    safeHttpCode.textContent = res.status || 'ERR';
    safeResponseBox.textContent = formatResponseBody(res.data);

    if (res.status === 400) {
      safeStatusBadge.textContent = '400 Bad Request';
      safeStatusBadge.className = 'status-badge status-400';
      safeVerdictBox.className = 'verdict-box safe-pass';
      safeVerdictBox.innerHTML = `
        <span class="status-dot dot-safe"></span><strong>Petición bloqueada:</strong> SsrfValidatorService detectó destino no autorizado (loopback/privada/esquema).
      `;
    } else if (res.status === 200) {
      safeStatusBadge.textContent = '200 OK';
      safeStatusBadge.className = 'status-badge status-200';
      safeVerdictBox.className = 'verdict-box safe-pass';
      safeVerdictBox.innerHTML = `
        <span class="status-dot dot-safe"></span><strong>Petición autorizada:</strong> Destino público válido que cumple las políticas de seguridad.
      `;
    } else if (res.status === 403) {
      safeStatusBadge.textContent = '403 Forbidden';
      safeStatusBadge.className = 'status-badge status-403';
      safeVerdictBox.className = 'verdict-box neutral';
      safeVerdictBox.innerHTML = `
        <span class="status-dot dot-neutral"></span><strong>Acceso denegado:</strong> Petición directa rechazada por rol insuficiente.
      `;
    } else {
      safeStatusBadge.textContent = `${res.status} Respuesta`;
      safeStatusBadge.className = 'status-badge status-500';
      safeVerdictBox.className = 'verdict-box neutral';
      safeVerdictBox.innerHTML = `
        <span class="status-dot dot-neutral"></span>Código HTTP ${res.status}.
      `;
    }

    recordAuditLog('Mitigado', scen.method, targetUrl, res.status, res.status === 400 ? 'SSRF bloqueado' : 'Aprobado/Respuesta');
  }

  btnRunComparison.addEventListener('click', async () => {
    btnRunComparison.disabled = true;
    btnRunComparison.innerHTML = '<span class="spinner"></span> Ejecutando';
    try {
      await Promise.all([runVulnerableScenario(), runMitigatedScenario()]);
      showToast('Comparación completada');
    } finally {
      btnRunComparison.disabled = false;
      btnRunComparison.textContent = 'Comparar ambos';
    }
  });

  btnRunVulnOnly.addEventListener('click', runVulnerableScenario);
  btnRunSafeOnly.addEventListener('click', runMitigatedScenario);

  // ==========================================
  // CONSOLA DE PETICIONES HTTP
  // ==========================================
  consoleEndpointType.addEventListener('change', () => {
    const val = consoleEndpointType.value;
    groupFullUrl.style.display = 'none';
    groupTargetUrl.style.display = 'flex';
    groupJsonBody.style.display = 'none';

    if (val === 'vuln-get') {
      consoleMethod.value = 'GET';
      consoleTargetUrl.value = `${BASE_URL}/internal/admin/claves-api`;
    } else if (val === 'vuln-post') {
      consoleMethod.value = 'POST';
      groupJsonBody.style.display = 'flex';
      consoleTargetUrl.value = `${BASE_URL}/internal/admin/claves-api`;
      consoleJsonBody.value = JSON.stringify({ url: consoleTargetUrl.value }, null, 2);
    } else if (val === 'safe-get') {
      consoleMethod.value = 'GET';
      consoleTargetUrl.value = `${BASE_URL}/internal/admin/claves-api`;
    } else if (val === 'safe-post') {
      consoleMethod.value = 'POST';
      groupJsonBody.style.display = 'flex';
      consoleTargetUrl.value = `${BASE_URL}/internal/admin/claves-api`;
      consoleJsonBody.value = JSON.stringify({ url: consoleTargetUrl.value }, null, 2);
    } else if (val === 'direct-keys') {
      consoleMethod.value = 'GET';
      consoleTargetUrl.value = `${BASE_URL}/internal/admin/claves-api`;
    } else if (val === 'direct-cloud') {
      consoleMethod.value = 'GET';
      consoleTargetUrl.value = `${BASE_URL}/latest/meta-data/iam/security-credentials`;
    } else if (val === 'custom') {
      groupTargetUrl.style.display = 'none';
      groupFullUrl.style.display = 'flex';
      if (consoleMethod.value === 'POST') groupJsonBody.style.display = 'flex';
    }
  });

  consoleMethod.addEventListener('change', () => {
    if (consoleMethod.value === 'POST') {
      groupJsonBody.style.display = 'flex';
      if (consoleJsonBody.value.trim() === '') {
        consoleJsonBody.value = JSON.stringify({ url: consoleTargetUrl.value }, null, 2);
      }
    } else {
      groupJsonBody.style.display = 'none';
    }
  });

  consoleTargetUrl.addEventListener('input', () => {
    if (consoleMethod.value === 'POST') {
      try {
        const obj = JSON.parse(consoleJsonBody.value);
        obj.url = consoleTargetUrl.value;
        consoleJsonBody.value = JSON.stringify(obj, null, 2);
      } catch (e) {
        // Ignorar si el usuario está editando JSON
      }
    }
  });

  btnConsoleSend.addEventListener('click', async () => {
    const epType = consoleEndpointType.value;
    const method = consoleMethod.value;
    let url = '';
    let fetchOptions = { method };

    if (epType === 'custom') {
      url = consoleFullUrl.value.trim();
    } else if (epType === 'vuln-get') {
      url = `${BASE_URL}/api/vulnerable/preview?url=${encodeURIComponent(consoleTargetUrl.value.trim())}`;
    } else if (epType === 'vuln-post') {
      url = `${BASE_URL}/api/vulnerable/fetch-url`;
      fetchOptions.headers = { 'Content-Type': 'application/json' };
      fetchOptions.body = consoleJsonBody.value.trim();
    } else if (epType === 'safe-get') {
      url = `${BASE_URL}/api/mitigado/preview?url=${encodeURIComponent(consoleTargetUrl.value.trim())}`;
    } else if (epType === 'safe-post') {
      url = `${BASE_URL}/api/mitigado/fetch-url`;
      fetchOptions.headers = { 'Content-Type': 'application/json' };
      fetchOptions.body = consoleJsonBody.value.trim();
    } else if (epType === 'direct-keys') {
      url = `${BASE_URL}/internal/admin/claves-api`;
    } else if (epType === 'direct-cloud') {
      url = `${BASE_URL}/latest/meta-data/iam/security-credentials`;
    }

    if (method === 'POST' && epType === 'custom') {
      fetchOptions.headers = { 'Content-Type': 'application/json' };
      fetchOptions.body = consoleJsonBody.value.trim();
    }

    consoleStatusBadge.innerHTML = '<span class="spinner"></span> Enviando';
    consoleStatusBadge.className = 'status-badge status-empty';
    consoleResponseBox.textContent = 'Esperando respuesta...';

    btnConsoleSend.disabled = true;
    try {
      const res = await doFetch(url, fetchOptions);

      consoleTimeStat.textContent = formatTime(res.duration);
      consoleStatusStat.textContent = `${res.status} ${res.statusText || ''}`;
      consoleTypeStat.textContent = res.headers ? (res.headers.get('content-type') || 'unknown') : 'N/A';
      consoleResponseBox.textContent = formatResponseBody(res.data);

      if (res.status === 200) {
        consoleStatusBadge.textContent = '200 OK';
        consoleStatusBadge.className = 'status-badge status-200';
        consoleVerdictBox.className = 'verdict-box safe-pass';
        consoleVerdictBox.innerHTML = `<span class="status-dot dot-safe"></span><strong>Petición exitosa:</strong> Código 200 OK recibido.`;
      } else if (res.status === 400) {
        consoleStatusBadge.textContent = '400 Bad Request';
        consoleStatusBadge.className = 'status-badge status-400';
        consoleVerdictBox.className = 'verdict-box vuln-fail';
        consoleVerdictBox.innerHTML = `<span class="status-dot dot-vuln"></span><strong>Petición rechazada:</strong> 400 Bad Request (Filtro SSRF o parámetro erróneo).`;
      } else if (res.status === 403) {
        consoleStatusBadge.textContent = '403 Forbidden';
        consoleStatusBadge.className = 'status-badge status-403';
        consoleVerdictBox.className = 'verdict-box vuln-fail';
        consoleVerdictBox.innerHTML = `<span class="status-dot dot-vuln"></span><strong>Acceso denegado:</strong> 403 Forbidden para el usuario actual.`;
      } else {
        consoleStatusBadge.textContent = `${res.status} Respuesta`;
        consoleStatusBadge.className = 'status-badge status-500';
        consoleVerdictBox.className = 'verdict-box neutral';
        consoleVerdictBox.innerHTML = `<span class="status-dot dot-neutral"></span>Código HTTP ${res.status}.`;
      }

      recordAuditLog(epType, method, consoleTargetUrl.value, res.status, `HTTP ${res.status}`);
      showToast(`HTTP ${res.status}`);
    } finally {
      btnConsoleSend.disabled = false;
    }
  });

  // ==========================================
  // REGISTRO DE AUDITORÍA
  // ==========================================
  function recordAuditLog(endpoint, method, targetUrl, status, diagnostic) {
    const now = new Date();
    const timeStr = now.toLocaleTimeString();

    const logEntry = {
      time: timeStr,
      user: currentUser.username,
      role: currentUser.role,
      endpoint,
      method,
      targetUrl,
      status,
      diagnostic
    };

    auditLogs.unshift(logEntry);
    renderAuditTable();
  }

  function renderAuditTable() {
    if (auditLogs.length === 0) {
      auditTableBody.innerHTML = `
        <tr>
          <td colspan="7" style="text-align:center;color:var(--text-muted);padding:20px;">
            Sin eventos registrados.
          </td>
        </tr>
      `;
      return;
    }

    auditTableBody.innerHTML = auditLogs.map(entry => {
      let badgeClass = 'status-200';
      if (entry.status === 400) badgeClass = 'status-400';
      else if (entry.status === 403) badgeClass = 'status-403';
      else if (entry.status >= 500 || entry.status === 0) badgeClass = 'status-500';

      return `
        <tr>
          <td class="font-mono-td" style="color:var(--text-muted);">${entry.time}</td>
          <td><span class="current-role-badge ${entry.user === 'admin' ? 'role-admin' : 'role-user'}">${entry.user}</span></td>
          <td><strong>${entry.endpoint}</strong></td>
          <td class="font-mono-td" style="color:var(--text-primary);">${entry.method}</td>
          <td class="font-mono-td" style="max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${entry.targetUrl}">${entry.targetUrl}</td>
          <td><span class="status-badge ${badgeClass}">${entry.status}</span></td>
          <td style="font-size:11px;">${entry.diagnostic}</td>
        </tr>
      `;
    }).join('');
  }

  btnClearHistory.addEventListener('click', () => {
    auditLogs.length = 0;
    renderAuditTable();
    showToast('Logs limpiados');
  });

  // ==========================================
  // COPIAR AL PORTAPAPELES
  // ==========================================
  btnCopyVuln.addEventListener('click', () => {
    navigator.clipboard.writeText(vulnResponseBox.textContent);
    showToast('Copiado');
  });

  btnCopySafe.addEventListener('click', () => {
    navigator.clipboard.writeText(safeResponseBox.textContent);
    showToast('Copiado');
  });

  btnCopyConsole.addEventListener('click', () => {
    navigator.clipboard.writeText(consoleResponseBox.textContent);
    showToast('Copiado');
  });

  // Inicialización
  updateAuthUI();
  selectScenario('cloud-metadata');
});
