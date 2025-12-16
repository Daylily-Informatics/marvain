/**
 * Memory Panel Component
 * Handles memory visualization, filtering, and search
 */

class MemoryPanel {
  constructor(containerId, options = {}) {
    this.container = document.getElementById(containerId);
    this.options = {
      refreshInterval: options.refreshInterval || 15000,
      limit: options.limit || 50,
      onMemorySelect: options.onMemorySelect || (() => {}),
    };
    this.memories = [];
    this.filter = { kind: 'ALL', speaker_id: null };
    this.searchTerm = '';
    this.init();
  }

  init() {
    if (!this.container) return;
    this.render();
    this.loadMemories();
    setInterval(() => this.loadMemories(), this.options.refreshInterval);
  }

  render() {
    this.container.innerHTML = `
      <div class="memory-panel">
        <div class="memory-panel-header">
          <h3>Memories</h3>
          <button class="btn btn-sm" onclick="memoryPanel.loadMemories()">↻ Refresh</button>
        </div>
        <div class="memory-filters">
          <select id="memoryKindFilter" onchange="memoryPanel.setKindFilter(this.value)">
            <option value="ALL">All Types</option>
            <option value="FACT">Facts</option>
            <option value="PREFERENCE">Preferences</option>
            <option value="RELATIONSHIP">Relationships</option>
            <option value="AI_INSIGHT">AI Insights</option>
            <option value="ACTION">Actions</option>
            <option value="META">Meta</option>
          </select>
          <input type="text" id="memorySearch" placeholder="Search memories..." 
                 oninput="memoryPanel.setSearch(this.value)" />
        </div>
        <div class="memory-stats" id="memoryStats"></div>
        <div class="memory-list" id="memoryList"></div>
      </div>
    `;
  }

  async loadMemories() {
    try {
      const params = new URLSearchParams({ limit: this.options.limit });
      if (this.filter.kind && this.filter.kind !== 'ALL') params.append('kind', this.filter.kind);
      if (this.filter.speaker_id) params.append('speaker_id', this.filter.speaker_id);
      const resp = await fetch(`/api/memories?${params}`);
      const data = await resp.json();
      this.memories = data.memories || [];
      this.renderMemories();
      this.renderStats(data);
    } catch (e) {
      console.error('Failed to load memories:', e);
    }
  }

  renderMemories() {
    const listEl = document.getElementById('memoryList');
    if (!listEl) return;
    
    let filtered = this.memories;
    if (this.searchTerm) {
      const term = this.searchTerm.toLowerCase();
      filtered = filtered.filter(m => 
        (m.text || '').toLowerCase().includes(term) ||
        (m.kind || '').toLowerCase().includes(term) ||
        (m.speaker_id || '').toLowerCase().includes(term)
      );
    }

    if (filtered.length === 0) {
      listEl.innerHTML = '<div class="no-data">No memories found</div>';
      return;
    }

    listEl.innerHTML = filtered.map(m => {
      const kind = m.kind || 'UNKNOWN';
      const kindClass = kind.toLowerCase().replace(/_/g, '-');
      const speaker = m.speaker_id || m.meta?.speaker_id || '';
      const importance = m.importance || m.meta?.importance;
      const ts = m.ts ? new Date(m.ts).toLocaleString() : '';
      return `
        <div class="memory-item ${kindClass}" onclick="memoryPanel.selectMemory('${m.sk || ''}')">
          <div class="memory-header">
            <span class="memory-kind-badge ${kindClass}">${kind}</span>
            ${importance ? `<span class="importance-badge">${importance}</span>` : ''}
            ${speaker ? `<span class="speaker-badge">👤 ${speaker}</span>` : ''}
          </div>
          <div class="memory-text">${m.text || ''}</div>
          ${ts ? `<div class="memory-ts">${ts}</div>` : ''}
        </div>
      `;
    }).join('');
  }

  renderStats(data) {
    const statsEl = document.getElementById('memoryStats');
    if (!statsEl) return;
    const total = data.total || this.memories.length;
    const byKind = {};
    this.memories.forEach(m => {
      const k = m.kind || 'UNKNOWN';
      byKind[k] = (byKind[k] || 0) + 1;
    });
    const kindStr = Object.entries(byKind).map(([k, v]) => `${k}: ${v}`).join(', ');
    statsEl.innerHTML = `<span>Total: ${total}</span> <span class="meta">${kindStr}</span>`;
  }

  setKindFilter(kind) {
    this.filter.kind = kind;
    this.loadMemories();
  }

  setSpeakerFilter(speakerId) {
    this.filter.speaker_id = speakerId;
    this.loadMemories();
  }

  setSearch(term) {
    this.searchTerm = term;
    this.renderMemories();
  }

  selectMemory(sk) {
    const mem = this.memories.find(m => m.sk === sk);
    if (mem) this.options.onMemorySelect(mem);
  }

  // Kind color mapping for inline styles
  static COLORS = {
    FACT: '#e3f2fd',
    PREFERENCE: '#fff3e0',
    AI_INSIGHT: '#f3e5f5',
    RELATIONSHIP: '#e8f5e9',
    ACTION: '#fce4ec',
    META: '#f5f5f5',
    UNKNOWN: '#fafafa'
  };
}

let memoryPanel = null;
function initMemoryPanel(containerId, options = {}) {
  memoryPanel = new MemoryPanel(containerId, options);
  return memoryPanel;
}
