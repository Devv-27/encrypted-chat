/*
 * Voice and video calls over WebRTC.
 *
 * Chat messages use the hand-rolled AES/RSA in this project. Call media
 * does not — WebRTC encrypts audio and video itself with DTLS-SRTP, in
 * the browser. What this file handles is signaling: passing an SDP
 * offer/answer and ICE candidates between two tabs over the websocket
 * we already have. The server relays those blindly, same as it relays
 * key_exchange.
 *
 * Two fixes worth knowing about:
 *
 * 1. Secure context. getUserMedia only exists on https:// or
 *    http://localhost. Opened off the disk you get file://, where
 *    navigator.mediaDevices is undefined — the call then failed with no
 *    permission prompt at all. getLocalStream() now names the cause.
 *
 * 2. Early ICE candidates. Candidates can arrive before the callee has
 *    a peer connection (still on the ringing screen), or before
 *    setRemoteDescription resolves. addIceCandidate() in that window
 *    throws or silently no-ops, which made calls connect only
 *    sometimes. They're buffered and flushed once a remote description
 *    exists.
 */

const ICE_SERVERS = { iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] };

let pc = null;
let localStream = null;
let callPeerId = null;
let callPeerName = null;
let isVideoCall = false;
let callState = 'idle';      // idle | calling | ringing | active
let pendingOffer = null;
let pendingIce = [];

function $c(id) { return document.getElementById(id); }

function resetCallUI() {
  $c('incomingCallModal').classList.add('hidden');
  $c('callOverlay').classList.add('hidden');
  $c('remoteVideo').srcObject = null;
  $c('localVideo').srcObject = null;
}

function teardownCall() {
  if (pc) { pc.close(); pc = null; }
  if (localStream) { localStream.getTracks().forEach(t => t.stop()); localStream = null; }
  callPeerId = null;
  callPeerName = null;
  callState = 'idle';
  pendingOffer = null;
  pendingIce = [];
  $c('muteBtn').textContent = 'Mute';
  $c('cameraBtn').textContent = 'Camera off';
  resetCallUI();
}

function sendSignal(obj) {
  if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(obj));
}

// returns a MediaStream, or null after telling the user why not
async function getLocalStream(video) {
  if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
    alert(
      'The browser is blocking microphone and camera access on this page.\n\n' +
      'That API only works on https:// or http://localhost, and this page is on ' +
      location.protocol + '//' + (location.host || '(local file)') + '.\n\n' +
      'Run `python serve.py` and open http://localhost:8000 instead.'
    );
    return null;
  }
  try {
    return await navigator.mediaDevices.getUserMedia({ audio: true, video });
  } catch (err) {
    const msg = {
      NotAllowedError: 'Permission was denied. Allow the microphone and camera from the icon in the address bar, then call again.',
      NotFoundError: video ? 'No camera found on this device.' : 'No microphone found on this device.',
      NotReadableError: 'The microphone or camera is already in use by another app or tab.',
      OverconstrainedError: 'No device matched what was requested.',
    }[err.name] || `${err.name}: ${err.message}`;
    alert(msg);
    return null;
  }
}

function flushPendingIce() {
  if (!pc || !pendingIce.length) return;
  const queued = pendingIce;
  pendingIce = [];
  for (const c of queued) pc.addIceCandidate(c).catch(() => {});
}

function buildPeerConnection() {
  const conn = new RTCPeerConnection(ICE_SERVERS);
  conn.onicecandidate = (e) => {
    if (e.candidate && callPeerId != null) {
      sendSignal({ type: 'call_ice', to: callPeerId, candidate: e.candidate });
    }
  };
  conn.ontrack = (e) => { $c('remoteVideo').srcObject = e.streams[0]; };
  conn.onconnectionstatechange = () => {
    if (conn !== pc) return;
    if (conn.connectionState === 'connected') $c('callStatusText').textContent = 'Connected';
    if (['disconnected', 'failed', 'closed'].includes(conn.connectionState) && callState !== 'idle') {
      teardownCall();
    }
  };
  return conn;
}

async function startCall(peerId, video) {
  if (callState !== 'idle') { toast('Already in a call'); return; }
  const user = users[peerId];
  if (!user) return;

  callPeerId = peerId;
  callPeerName = user.username;
  isVideoCall = video;
  callState = 'calling';

  localStream = await getLocalStream(video);
  if (!localStream) { teardownCall(); return; }

  pc = buildPeerConnection();
  localStream.getTracks().forEach(t => pc.addTrack(t, localStream));

  const offer = await pc.createOffer();
  await pc.setLocalDescription(offer);
  sendSignal({ type: 'call_offer', to: peerId, sdp: offer.sdp, video });

  showCallOverlay('Calling…', video);
}

async function acceptCall() {
  if (!pendingOffer) return;
  const { from, sdp, video } = pendingOffer;
  pendingOffer = null;
  callPeerId = from;
  callPeerName = users[from] ? users[from].username : 'Unknown';
  isVideoCall = video;
  callState = 'active';
  $c('incomingCallModal').classList.add('hidden');

  localStream = await getLocalStream(video);
  if (!localStream) {
    sendSignal({ type: 'call_reject', to: from });
    teardownCall();
    return;
  }

  pc = buildPeerConnection();
  localStream.getTracks().forEach(t => pc.addTrack(t, localStream));
  await pc.setRemoteDescription({ type: 'offer', sdp });
  flushPendingIce();
  const answer = await pc.createAnswer();
  await pc.setLocalDescription(answer);
  sendSignal({ type: 'call_answer', to: from, sdp: answer.sdp });

  showCallOverlay('Connecting…', video);
}

function rejectCall() {
  if (pendingOffer) sendSignal({ type: 'call_reject', to: pendingOffer.from });
  $c('incomingCallModal').classList.add('hidden');
  pendingOffer = null;
  pendingIce = [];
  callState = 'idle';
}

function hangUp() {
  if (callPeerId != null) sendSignal({ type: 'call_end', to: callPeerId });
  teardownCall();
}

function toggleMute() {
  const track = localStream && localStream.getAudioTracks()[0];
  if (!track) return;
  track.enabled = !track.enabled;
  $c('muteBtn').textContent = track.enabled ? 'Mute' : 'Unmute';
}

function toggleCamera() {
  const track = localStream && localStream.getVideoTracks()[0];
  if (!track) return;
  track.enabled = !track.enabled;
  $c('cameraBtn').textContent = track.enabled ? 'Camera off' : 'Camera on';
}

function showCallOverlay(status, video) {
  $c('callOverlay').classList.remove('hidden');
  $c('callPeerName').textContent = callPeerName;
  $c('callStatusText').textContent = status;
  $c('localVideo').srcObject = localStream;
  $c('videoArea').classList.toggle('audio-only', !video);
  $c('callAudioBadge').textContent = 'Voice call';
  $c('cameraBtn').classList.toggle('hidden', !video);
}

// called from app.js handleMessage for call_* types
function handleCallSignal(data) {
  switch (data.type) {
    case 'call_offer': {
      if (callState !== 'idle') { sendSignal({ type: 'call_reject', to: data.from }); return; }
      pendingOffer = data;
      pendingIce = [];
      callState = 'ringing';
      const caller = users[data.from];
      const name = caller ? caller.username : 'Unknown';
      $c('incomingCallerName').textContent = name;
      $c('incomingCallType').textContent = data.video ? 'Video call' : 'Voice call';

      const slot = $c('incomingAvatar');
      slot.innerHTML = '';
      if (caller && caller.avatar) {
        const img = document.createElement('img');
        img.src = caller.avatar;
        img.alt = '';
        slot.appendChild(img);
        slot.style.background = 'transparent';
      } else {
        slot.textContent = name.charAt(0).toUpperCase();
        slot.style.background = colorFor(name);
      }
      $c('incomingCallModal').classList.remove('hidden');
      break;
    }

    case 'call_answer': {
      if (pc && callPeerId === data.from) {
        pc.setRemoteDescription({ type: 'answer', sdp: data.sdp })
          .then(flushPendingIce)
          .catch(() => {});
        callState = 'active';
      }
      break;
    }

    case 'call_ice': {
      if (!data.candidate) break;
      const fromPeer = callPeerId === data.from || (pendingOffer && pendingOffer.from === data.from);
      if (!fromPeer) break;
      // may land while still ringing (no pc yet) or before the remote
      // description resolves — buffer rather than drop
      if (pc && pc.remoteDescription && pc.remoteDescription.type) {
        pc.addIceCandidate(data.candidate).catch(() => {});
      } else {
        pendingIce.push(data.candidate);
      }
      break;
    }

    case 'call_reject': {
      if (callPeerId === data.from) {
        log(`${callPeerName || 'They'} declined the call`);
        teardownCall();
      }
      break;
    }

    case 'call_end': {
      if (callPeerId === data.from) {
        log('Call ended');
        teardownCall();
      } else if (pendingOffer && pendingOffer.from === data.from) {
        $c('incomingCallModal').classList.add('hidden');
        pendingOffer = null;
        pendingIce = [];
        callState = 'idle';
      }
      break;
    }
  }
}

$c('acceptCallBtn').addEventListener('click', acceptCall);
$c('rejectCallBtn').addEventListener('click', rejectCall);
$c('hangupBtn').addEventListener('click', hangUp);
$c('muteBtn').addEventListener('click', toggleMute);
$c('cameraBtn').addEventListener('click', toggleCamera);