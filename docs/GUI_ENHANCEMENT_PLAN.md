# GUI Enhancement Plan for Rank 4/5 Voice Agent Testing

## Summary

The current GUI provides a good foundation but needs enhancements to fully support
testing the Rank 4/5 improvements. This document outlines the required changes.

## Priority 1: Critical Fixes

### 1.1 Fix Session ID in WebSocket
**Location:** `client/templates/chat.html` line 503
**Issue:** Session ID is hardcoded to `'ui-session'`
**Fix:** Use the selected session from state

```javascript
// Change from:
session_id: 'ui-session',
// To:
session_id: '{{ state.selected_session or "" }}' || null,
```

### 1.2 Add Speaker Identification Display
**Add to chat.html:**
- Speaker badge showing current speaker name/ID
- Visual indicator for "new speaker" vs "recognized speaker"
- Display speaker confidence score from broker response

## Priority 2: New API Endpoints Required

### 2.1 Memory API Endpoints
```python
@app.get("/api/memories")
async def get_memories(
    limit: int = 50,
    speaker_id: Optional[str] = None,
    kind: Optional[str] = None,
):
    """Retrieve memories with filtering."""

@app.get("/api/speakers")
async def list_speakers():
    """List all known speakers for the current agent."""

@app.get("/api/speakers/{speaker_id}")
async def get_speaker_profile(speaker_id: str):
    """Get detailed speaker profile."""
```

### 2.2 Tool Execution Status Endpoint
```python
@app.get("/api/tool_status")
async def get_tool_status():
    """Get status of recent tool executions."""
```

### 2.3 Voice Enrollment Endpoints
```python
@app.post("/api/speakers/enroll")
async def enroll_speaker(
    speaker_name: str = Form(...),
    audio_file: UploadFile = File(...),
):
    """Enroll a new speaker with voice sample."""
```

## Priority 3: UI Enhancements

### 3.1 Speaker Panel (New Component)
- List of known speakers
- Click to view speaker profile
- Voice enrollment button
- Speaker-specific memory view

### 3.2 Memory Visualization Panel
- Real-time memory feed
- Filter by type (FACT, PREFERENCE, etc.)
- Filter by speaker
- Importance indicators (color-coded)
- Relationship summary display

### 3.3 Tool Execution Panel
- Show when tools are being executed
- Display iteration count (e.g., "Tool iteration 2/5")
- Show tool results inline
- Expandable details for each tool call

## Priority 4: Cross-Platform Considerations

### 4.1 Browser Compatibility
- Test WebSocket ASR on Firefox/Safari
- Ensure Web Audio API fallbacks work
- Test audio device selection on Linux

### 4.2 Mobile Support (Future)
- Responsive layout adjustments
- Touch-friendly controls for PTT

## Implementation Order

1. **Phase 1 (Immediate):** Fix session_id bug, add speaker display
2. **Phase 2 (Short-term):** Add memory and speaker API endpoints
3. **Phase 3 (Medium-term):** Build new UI panels
4. **Phase 4 (Long-term):** Voice enrollment workflow, mobile support

## Files to Modify

- `client/gui.py` - Add new API endpoints
- `client/templates/chat.html` - UI enhancements
- `client/templates/home.html` - Speaker/memory quick view
- `client/identity.py` - Integrate with new VoiceRegistry

## New Files to Create

- `client/templates/speakers.html` - Speaker management page
- `client/templates/memories.html` - Memory visualization page
- `client/static/js/speaker-panel.js` - Speaker UI component
- `client/static/js/memory-panel.js` - Memory UI component

