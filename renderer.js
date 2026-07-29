document.addEventListener('DOMContentLoaded', () => {
  // Elements
  const refreshStatusBtn = document.getElementById('refreshStatusBtn');
  const askInput = document.getElementById('askInput');
  const askBtn = document.getElementById('askBtn');
  const socOutput = document.getElementById('socOutput');
  const configPathInput = document.getElementById('configPathInput');
  const planScanBtn = document.getElementById('planScanBtn');
  const plannerOutput = document.getElementById('plannerOutput');
  const toolsTableBody = document.getElementById('toolsTableBody');
  const skillsList = document.getElementById('skillsList');
  const skillDetailOutput = document.getElementById('skillDetailOutput');

  // Metrics
  const metricSkillsCount = document.getElementById('metricSkillsCount');
  const metricToolsCount = document.getElementById('metricToolsCount');
  const metricBuiltInTools = document.getElementById('metricBuiltInTools');
  const metricExecutableTools = document.getElementById('metricExecutableTools');
  const metricIntegrityVerified = document.getElementById('metricIntegrityVerified');

  // Init
  loadStatus();
  loadTools();
  loadSkills();

  // Tab switching
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));

      btn.classList.add('active');
      const tabId = btn.getAttribute('data-tab');
      document.getElementById(tabId).classList.add('active');
    });
  });

  // Health / Offline status
  refreshStatusBtn.addEventListener('click', () => loadStatus());

  async function loadStatus() {
    refreshStatusBtn.innerText = 'Checking...';
    try {
      const res = await window.electronAPI.getOfflineStatus();
      if (res.success && res.metrics) {
        metricSkillsCount.innerText = res.metrics['embedded_skills'] || '--';
        metricToolsCount.innerText = res.metrics['cataloged_tool_definitions'] || '--';
        metricBuiltInTools.innerText = res.metrics['built_in_substitute_tools'] || '--';
        metricExecutableTools.innerText = res.metrics['locally_executable_tools'] || '--';
        metricIntegrityVerified.innerText = res.metrics['integrity_verified_tools'] || '--';
      }
    } catch (err) {
      console.error('Status check error:', err);
    } finally {
      refreshStatusBtn.innerText = 'Check Health';
    }
  }

  // Ask AI query
  askBtn.addEventListener('click', async () => {
    const query = askInput.value.trim();
    if (!query) return;

    askBtn.disabled = true;
    askBtn.innerText = 'Processing...';
    socOutput.innerText = `Executing grounded instruction query: "${query}"...\n`;

    try {
      const res = await window.electronAPI.askAgent(query);
      socOutput.innerText = res.response;
    } catch (err) {
      socOutput.innerText = `Error: ${err.message}`;
    } finally {
      askBtn.disabled = false;
      askBtn.innerText = 'Execute Query';
    }
  });

  askInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') askBtn.click();
  });

  // Plan Scan
  planScanBtn.addEventListener('click', async () => {
    const pathVal = configPathInput.value.trim();
    if (!pathVal) return;

    planScanBtn.disabled = true;
    planScanBtn.innerText = 'Planning...';
    plannerOutput.innerText = `Planning authorized scan for config: ${pathVal}...\n`;

    try {
      const res = await window.electronAPI.planScan(pathVal);
      plannerOutput.innerText = res.output;
    } catch (err) {
      plannerOutput.innerText = `Plan error: ${err.message}`;
    } finally {
      planScanBtn.disabled = false;
      planScanBtn.innerText = 'Plan Authorized Scan';
    }
  });

  // Load Tools
  async function loadTools() {
    try {
      const res = await window.electronAPI.listTools();
      if (res.success && res.tools) {
        toolsTableBody.innerHTML = res.tools.map(tool => `
          <tr>
            <td style="font-weight: 600; color: var(--neon-cyan);">${tool.name}</td>
            <td>${tool.type}</td>
            <td>${tool.details}</td>
          </tr>
        `).join('');
      }
    } catch (err) {
      toolsTableBody.innerHTML = `<tr><td colspan="3">Failed to load tools: ${err.message}</td></tr>`;
    }
  }

  // Load Skills
  async function loadSkills() {
    try {
      const res = await window.electronAPI.listSkills();
      if (res.success && res.skills) {
        skillsList.innerHTML = res.skills.map(skill => `
          <button class="btn btn-secondary skill-item-btn" style="width: 100%; text-align: left; font-size: 12px;" data-skill="${skill}">
            ${skill}
          </button>
        `).join('');

        document.querySelectorAll('.skill-item-btn').forEach(btn => {
          btn.addEventListener('click', async () => {
            const skillName = btn.getAttribute('data-skill');
            skillDetailOutput.innerText = `Loading playbook '${skillName}'...`;
            const sRes = await window.electronAPI.showSkill(skillName);
            skillDetailOutput.innerText = sRes.content;
          });
        });
      }
    } catch (err) {
      skillsList.innerHTML = `<span style="color: var(--neon-red)">Error loading skills</span>`;
    }
  }
});
