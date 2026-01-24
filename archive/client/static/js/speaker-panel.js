/**
 * Speaker Panel Component
 * Handles speaker management, enrollment, and profile display
 */

class SpeakerPanel {
  constructor(containerId, options = {}) {
    this.container = document.getElementById(containerId);
    this.options = {
      onSpeakerSelect: options.onSpeakerSelect || (() => {}),
      onEnrollmentComplete: options.onEnrollmentComplete || (() => {}),
      refreshInterval: options.refreshInterval || 30000,
    };
    this.speakers = [];
    this.selectedSpeaker = null;
    this.isRecording = false;
    this.mediaRecorder = null;
    this.audioChunks = [];
    this.enrollmentSamples = [];
    this.init();
  }

  init() {
    if (!this.container) {
      console.error('SpeakerPanel: Container not found');
      return;
    }
    this.render();
    this.loadSpeakers();
    setInterval(() => this.loadSpeakers(), this.options.refreshInterval);
  }

  render() {
    this.container.innerHTML = `
      <div class="speaker-panel">
        <div class="speaker-panel-header">
          <h3>Speakers</h3>
          <button class="btn btn-sm" onclick="speakerPanel.showEnrollmentModal()">+ Enroll</button>
        </div>
        <div class="speaker-list" id="speakerList">
          <div class="no-speakers">Loading speakers...</div>
        </div>
        <div class="speaker-detail" id="speakerDetail" style="display: none;"></div>
      </div>
      <div class="modal" id="enrollmentModal" style="display: none;">
        <div class="modal-content">
          <div class="modal-header">
            <h3>Enroll New Speaker</h3>
            <button class="btn-close" onclick="speakerPanel.hideEnrollmentModal()">&times;</button>
          </div>
          <div class="modal-body">
            <div class="form-group">
              <label>Speaker Name</label>
              <input type="text" id="enrollSpeakerName" placeholder="Enter name" />
            </div>
            <div class="form-group">
              <label>Voice Samples (record 1-5 samples)</label>
              <div class="recording-controls">
                <button id="recordBtn" class="btn" onclick="speakerPanel.toggleRecording()">🎤 Record</button>
                <span id="recordingStatus" class="recording-status"></span>
              </div>
              <div id="samplesList" class="samples-list"></div>
            </div>
            <div class="enrollment-progress" id="enrollmentProgress" style="display: none;">
              <div class="progress-bar"><div class="progress-fill" id="progressFill"></div></div>
              <span id="progressText">0/3 samples</span>
            </div>
          </div>
          <div class="modal-footer">
            <button class="btn" onclick="speakerPanel.hideEnrollmentModal()">Cancel</button>
            <button class="btn btn-primary" id="enrollBtn" onclick="speakerPanel.submitEnrollment()" disabled>Enroll</button>
          </div>
        </div>
      </div>
    `;
  }

  async loadSpeakers() {
    try {
      console.log('SpeakerPanel: Loading speakers...');
      const resp = await fetch('/api/speakers');
      const data = await resp.json();
      console.log('SpeakerPanel: Received data:', data);
      this.speakers = data.speakers || [];
      this.renderSpeakerList();
    } catch (e) {
      console.error('SpeakerPanel: Failed to load speakers:', e);
      const listEl = document.getElementById('speakerList');
      if (listEl) listEl.innerHTML = '<div class="no-speakers">Failed to load speakers</div>';
    }
  }

  renderSpeakerList() {
    const listEl = document.getElementById('speakerList');
    if (!listEl) return;
    if (this.speakers.length === 0) {
      listEl.innerHTML = '<div class="no-speakers">No speakers enrolled yet</div>';
      return;
    }
    listEl.innerHTML = this.speakers.map(s => `
      <div class="speaker-item ${this.selectedSpeaker?.speaker_id === s.speaker_id ? 'selected' : ''}"
           onclick="speakerPanel.selectSpeaker('${s.speaker_id}')">
        <div class="speaker-avatar">${(s.speaker_name || 'U')[0].toUpperCase()}</div>
        <div class="speaker-info">
          <div class="speaker-name">${s.speaker_name || 'Unknown'}</div>
          <div class="speaker-meta">
            <span class="badge ${s.enrollment_status || 'unknown'}">${s.enrollment_status || 'unknown'}</span>
            <span>${s.interaction_count || 0} chats</span>
          </div>
        </div>
      </div>
    `).join('');
  }

  async selectSpeaker(speakerId) {
    try {
      const resp = await fetch(`/api/speakers/${speakerId}`);
      const data = await resp.json();
      this.selectedSpeaker = data.profile;
      this.renderSpeakerDetail(data);
      this.renderSpeakerList();
      this.options.onSpeakerSelect(this.selectedSpeaker);
    } catch (e) {
      console.error('SpeakerPanel: Failed to load speaker:', e);
    }
  }

  renderSpeakerDetail(data) {
    const detailEl = document.getElementById('speakerDetail');
    if (!detailEl || !data.profile) return;
    const p = data.profile;
    const mems = data.memories || [];
    detailEl.style.display = 'block';
    detailEl.innerHTML = `
      <div class="detail-header">
        <button class="btn-back" onclick="speakerPanel.hideDetail()">← Back</button>
        <h4>${p.speaker_name || 'Unknown'}</h4>
      </div>
      <div class="detail-content">
        <div class="detail-section">
          <h5>Profile</h5>
          <div class="detail-grid">
            <div><strong>ID:</strong> ${p.speaker_id}</div>
            <div><strong>Status:</strong> <span class="badge ${p.enrollment_status || 'unknown'}">${p.enrollment_status || 'unknown'}</span></div>
            <div><strong>First:</strong> ${p.first_seen ? new Date(p.first_seen).toLocaleDateString() : 'N/A'}</div>
            <div><strong>Chats:</strong> ${p.interaction_count || 0}</div>
          </div>
        </div>
        <div class="detail-section">
          <h5>Memories (${mems.length})</h5>
          <div class="memory-list">${mems.length === 0 ? '<div class="no-data">No memories</div>' : 
            mems.slice(0, 10).map(m => `<div class="memory-item ${(m.kind || '').toLowerCase()}">
              <span class="memory-kind">[${m.kind || '?'}]</span> ${m.text || ''}</div>`).join('')}
          </div>
        </div>
      </div>
    `;
  }

  hideDetail() {
    const detailEl = document.getElementById('speakerDetail');
    if (detailEl) detailEl.style.display = 'none';
    this.selectedSpeaker = null;
    this.renderSpeakerList();
  }

  showEnrollmentModal() {
    console.log('SpeakerPanel: showEnrollmentModal called');
    const modal = document.getElementById('enrollmentModal');
    if (modal) {
      modal.style.display = 'flex';
      console.log('SpeakerPanel: Modal display set to flex');
    } else {
      console.error('SpeakerPanel: Modal element not found');
    }
    this.audioChunks = [];
    this.enrollmentSamples = [];
    this.updateEnrollmentProgress();
  }

  hideEnrollmentModal() {
    const modal = document.getElementById('enrollmentModal');
    if (modal) modal.style.display = 'none';
    this.stopRecording();
    const nameEl = document.getElementById('enrollSpeakerName');
    const samplesEl = document.getElementById('samplesList');
    if (nameEl) nameEl.value = '';
    if (samplesEl) samplesEl.innerHTML = '';
    this.enrollmentSamples = [];
  }

  async toggleRecording() {
    if (this.isRecording) {
      this.stopRecording();
    } else {
      await this.startRecording();
    }
  }

  async startRecording() {
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      this.mediaRecorder = new MediaRecorder(stream);
      this.audioChunks = [];
      this.mediaRecorder.ondataavailable = (e) => this.audioChunks.push(e.data);
      this.mediaRecorder.onstop = () => {
        const audioBlob = new Blob(this.audioChunks, { type: 'audio/wav' });
        this.addSample(audioBlob);
        stream.getTracks().forEach(t => t.stop());
      };
      this.mediaRecorder.start();
      this.isRecording = true;
      this.updateRecordingUI();
      setTimeout(() => { if (this.isRecording) this.stopRecording(); }, 5000);
    } catch (e) {
      console.error('SpeakerPanel: Recording failed:', e);
      alert('Could not access microphone. Please check permissions.');
    }
  }

  stopRecording() {
    if (this.mediaRecorder && this.isRecording) {
      this.mediaRecorder.stop();
      this.isRecording = false;
      this.updateRecordingUI();
    }
  }

  updateRecordingUI() {
    const btn = document.getElementById('recordBtn');
    const status = document.getElementById('recordingStatus');
    if (this.isRecording) {
      if (btn) btn.textContent = '⏹ Stop';
      if (status) { status.textContent = 'Recording...'; status.classList.add('active'); }
    } else {
      if (btn) btn.textContent = '🎤 Record';
      if (status) { status.textContent = ''; status.classList.remove('active'); }
    }
  }

  addSample(audioBlob) {
    this.enrollmentSamples.push(audioBlob);
    this.updateEnrollmentProgress();
    this.renderSamplesList();
  }

  renderSamplesList() {
    const listEl = document.getElementById('samplesList');
    if (!listEl) return;
    listEl.innerHTML = this.enrollmentSamples.map((sample, i) => `
      <div class="sample-item">
        <span>Sample ${i + 1}</span>
        <audio controls src="${URL.createObjectURL(sample)}"></audio>
        <button class="btn-sm" onclick="speakerPanel.removeSample(${i})">✕</button>
      </div>
    `).join('');
  }

  removeSample(index) {
    this.enrollmentSamples.splice(index, 1);
    this.updateEnrollmentProgress();
    this.renderSamplesList();
  }

  updateEnrollmentProgress() {
    const count = this.enrollmentSamples?.length || 0;
    const progressEl = document.getElementById('enrollmentProgress');
    const fillEl = document.getElementById('progressFill');
    const textEl = document.getElementById('progressText');
    const enrollBtn = document.getElementById('enrollBtn');
    if (progressEl) progressEl.style.display = count > 0 ? 'block' : 'none';
    if (fillEl) fillEl.style.width = `${Math.min(count / 3, 1) * 100}%`;
    if (textEl) textEl.textContent = `${count}/3 samples`;
    if (enrollBtn) enrollBtn.disabled = count < 1;
  }

  async submitEnrollment() {
    const nameInput = document.getElementById('enrollSpeakerName');
    const name = nameInput?.value.trim();
    if (!name) { alert('Please enter a speaker name'); return; }
    if (this.enrollmentSamples.length < 1) { alert('Please record at least one voice sample'); return; }
    
    const formData = new FormData();
    formData.append('speaker_name', name);
    this.enrollmentSamples.forEach((sample, i) => {
      formData.append('audio_files', sample, `sample_${i}.wav`);
    });
    
    try {
      console.log('SpeakerPanel: Submitting enrollment for', name);
      const resp = await fetch('/api/speakers/enroll', { method: 'POST', body: formData });
      const data = await resp.json();
      console.log('SpeakerPanel: Enrollment response:', data);
      if (data.error) { 
        alert('Enrollment failed: ' + data.error); 
      } else { 
        this.hideEnrollmentModal(); 
        this.loadSpeakers(); 
        this.options.onEnrollmentComplete(data);
        alert('Speaker enrolled successfully!');
      }
    } catch (e) {
      console.error('SpeakerPanel: Enrollment failed:', e);
      alert('Enrollment failed: ' + e.message);
    }
  }
}

// Global instance
let speakerPanel = null;

function initSpeakerPanel(containerId, options = {}) {
  console.log('initSpeakerPanel called with containerId:', containerId);
  speakerPanel = new SpeakerPanel(containerId, options);
  return speakerPanel;
}
