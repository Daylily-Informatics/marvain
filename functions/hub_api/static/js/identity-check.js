/* User-triggered capture only; a check is bound to one sign-in and operation. */
Marvain.sensitiveFetch = async function(url, options = {}) {
  let response = await fetch(Marvain.path(url), options);
  if (response.status !== 428) return response;
  const required = (await response.json()).detail;
  if (required.code !== 'identity_check_required') throw new Error('Identity check unavailable');
  Marvain.hideLoading();
  const checkId = await new Promise((resolve, reject) => {
    const dialog = document.createElement('dialog');
    dialog.style.cssText = 'max-width:540px;width:90%;padding:24px;color:inherit;background:var(--color-gray-800,#20242a)';
    dialog.innerHTML = `<h3>Confirm your identity</h3>
      <p>Use your enrolled voice or face to corroborate this sign-in. This check is valid for this operation for five minutes.</p>
      <label>Capture space <select id="identity-space"></select></label>
      <label>Use <select id="identity-modality"><option value="face">Face</option><option value="voice">Voice</option><option value="both">Voice and face</option></select></label>
      <p>Face: one person in view. Voice: say your name and today’s date. This is an identity signal, not proof of liveness.</p>
      <video autoplay playsinline muted style="width:100%;max-height:200px" hidden></video>
      <p role="status"></p><button type="button" data-start>Start capture</button>
      <button type="button" data-stop disabled>Submit sample</button>
      <button type="button" data-finish disabled>Continue with operation</button>
      <button type="button" data-cancel>Cancel</button>`;
    document.body.appendChild(dialog);
    const space = dialog.querySelector('#identity-space');
    space.add(new Option('Choose a space', ''));
    required.spaces.forEach(s => space.add(new Option(s.name, s.space_id)));
    const status = dialog.querySelector('[role=status]');
    const start = dialog.querySelector('[data-start]'), stop = dialog.querySelector('[data-stop]');
    const finish = dialog.querySelector('[data-finish]'), modality = dialog.querySelector('#identity-modality');
    let stream, recorder, chunks, check, remaining = [], active, completed = false;
    function stopTracks() { if(stream) stream.getTracks().forEach(t=>t.stop()); stream=null; }
    function close() { stopTracks(); dialog.close(); dialog.remove(); }
    dialog.addEventListener('cancel', e => { e.preventDefault(); close(); reject(new Error('Identity check cancelled')); });
    dialog.querySelector('[data-cancel]').onclick = () => { close(); reject(new Error('Identity check cancelled')); };
    start.onclick = async () => {
      try {
        if (!space.value) throw new Error('Choose a capture space');
        if (!check) {
          remaining = modality.value==='both' ? ['face','voice'] : [modality.value];
          const r = await fetch(Marvain.path('/api/identity-checks'), {method:'POST',headers:{'Content-Type':'application/json'},
            body:JSON.stringify({...required,space_id:space.value,modalities:remaining})});
          const body = await r.json();
          if(!r.ok) throw new Error(body.detail || 'Cannot start identity check');
          check=body.check_id; space.disabled=true; modality.disabled=true;
        }
        active=remaining[0];
        stream=await navigator.mediaDevices.getUserMedia(active==='face' ? {video:true} : {audio:true});
        if(active==='face') { const video=dialog.querySelector('video'); video.hidden=false; video.srcObject=stream; await video.play(); }
        else { chunks=[]; recorder=new MediaRecorder(stream); recorder.ondataavailable=e=>{if(e.data.size)chunks.push(e.data);}; recorder.start(); }
        status.textContent=active==='face' ? 'Frame one face, then submit.' : 'Recording. Say your name and today’s date, then submit.';
        start.disabled=true; stop.disabled=false;
      } catch(e) { stopTracks(); status.textContent=e.message; }
    };
    stop.onclick=async()=>{
      stop.disabled=true;
      try {
        let blob;
        if(active==='face') {
          const video=dialog.querySelector('video'), canvas=document.createElement('canvas');
          canvas.width=video.videoWidth; canvas.height=video.videoHeight;
          canvas.getContext('2d').drawImage(video,0,0);
          blob=await new Promise(r=>canvas.toBlob(r,'image/jpeg',0.9));
        } else {
          blob=await new Promise(r=>{recorder.onstop=()=>r(new Blob(chunks,{type:recorder.mimeType}));recorder.stop();});
        }
        stopTracks();
        const form=new FormData();
        form.append('agent_id',required.agent_id); form.append('space_id',space.value);
        form.append('check_id',check); form.append('modality',active); form.append('file',blob,active==='face'?'face.jpg':'voice.webm');
        const r=await fetch(Marvain.path('/api/recognition/captures'),{method:'POST',body:form});
        const body=await r.json(); if(!r.ok) throw new Error(body.detail || 'Capture failed');
        remaining.shift();
        completed=remaining.length===0;
        start.disabled=completed; finish.disabled=!completed;
        status.textContent=completed ? 'Samples submitted. Continue when processing has completed.' : 'Face submitted. Start the voice capture next.';
      } catch(e) {stopTracks(); status.textContent=e.message + '. Cancel and start a new check to retry.';}
    };
    finish.onclick=()=>{ if(completed){close();resolve(check);} };
    dialog.showModal();
  });
  response = await fetch(Marvain.path(url), {...options, headers:{...(options.headers||{}),'X-Marvain-Identity-Check':checkId}});
  return response;
};

Marvain.exportSessionMemory = async function(sessionId) {
  try {
    const response=await Marvain.sensitiveFetch(`/api/sessions/${sessionId}/memory-export`,{method:'POST'});
    if(!response.ok) throw new Error((await response.json()).detail || 'Export failed');
    const url=URL.createObjectURL(await response.blob()), link=document.createElement('a');
    link.href=url; link.download=`marvain-memory-${sessionId}.json`; link.click(); URL.revokeObjectURL(url);
  } catch(e) {Marvain.showToast('error','Export',e.message);}
};
