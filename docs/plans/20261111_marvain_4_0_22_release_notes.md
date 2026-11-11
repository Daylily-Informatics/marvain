# Marvain 4.0.22 — overnight checkpoint

This Git release records the completed dog-photo upload and responder startup work, attended results, and the paused continuation plan. Since 4.0.21, changes are documentation only; production remains on Hub/responder 4.0.21 and recognition image 4.0.19.

- Uploaded dog photos are stored successfully independently of detection. Detection and caretaker approval have separate states. Chunk2 has an approved reference.
- Browser joins use unique media rooms so a failed prior responder does not prevent a new dispatch.
- Startup memory recall reuses canonical TapDB objects and lineage within one transaction, preserving access and retention rules. Blocking startup HTTP no longer stalls the audio event loop.
- Attended Chrome results: responder ready, spoken greeting, current camera acknowledgment, and a fresh face comparison identifying John with Mic Off.
- Individual-dog matching is still pending. A generic description of a dog is not an identity-comparison result.

The live session was disconnected for the night with camera and microphone off. Existing hosted services remain in place; no rebuild, deployment, PR, merge, automated test campaign, or package publication accompanies this checkpoint.

Resume from the existing execution ledger after an explicit user instruction. Next step: show the dog in Live Session and type “Recognize the dog from the camera.”
