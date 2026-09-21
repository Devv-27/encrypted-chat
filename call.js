/*
 * Voice + video calling over WebRTC. Chat messages use our own
 * hand-rolled AES/RSA, but call audio/video does NOT - WebRTC media is
 * encrypted end-to-end by the browser (DTLS-SRTP). What this file does
 * is the "signaling": passing an SDP offer/answer and ICE candidates
 * between two browsers over our existing websocket.
 *
 * Two fixes worth knowing about:
 *
 * 1. Secure context. getUserMedia only works on https:// or
 *    http://localhost. Opening index.html off the disk gives you
 *    file://, where navigator.mediaDevices is undefined, so the call
 *    failed with no permission prompt at all. getLocalStream() now
 *    says so explicitly instead of throwing something cryptic.
 *
 * 2. Early ICE candidates. Candidates can arrive before the receiving
 *    side has a peer connection (the callee is still "ringing"), or
 *    before setRemoteDescription resolves. addIceCandidate() in that
 *    window throws or silently no-ops, which made calls connect
 *    inconsistently. They're buffered in pendingIce and flushed once a
 *    remote description exists.
 */

const ICE_SERVERS = { iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] };

let pc = null;
let localStream = null;
let callPeerId = null;
let callPeerName = null;
let isVideoCall = false;
let callState = 'idle';    // idle | calling | ringing | active
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
  resetCallUI();
}

function sendSignal(obj) {
  ws.send(JSON.stringify(obj));
}

// returns a MediaStream or null (and has already alerted the user).
async function getLocalStream(video) {
  if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
    alert(
      'The browser will not give this page microphone/camera access.\n\n' +
      'That API is only available on https:// or http://localhost, and this page is on ' +
      location.protocol + '//' + (location.host || '(local file)') + '.\n\n' +
      'Run `python serve.py` and open http://localhost:8000 instead of the file:// path.'
    );
    return null;
  }
  try {
    return await navigator.mediaDevices.getUserMedia({ audio: true, video });
  } catch (err) {
    if (err.name === 'NotAllowedError') {
      alert('Microphone/camera permission was denied. Click the camera icon in the address bar and allow it, then try again.');
    } else if (err.name === 'NotFoundError') {
      alert(video ? 'No camera found on this device.' : 'No microphone found on this device.');
    } else if (err.name === 'NotReadableError') {
      alert('The microphone/camera is already in use by another app or tab.');
    } else {
      alert('Could not access microphone/camera: ' + err.name + ' - ' + err.message);
    }
    return null;
  }
}

function flushPendingIce() {
  if (!pc || !pendingIce.length) return;
  const queued = pendingIce;
  pendingIce = [];
  for (const candidate of queued) {
    pc.addIceCandidate(candidate).catch(() => {});
  }
}

function buildPeerConnection() {
  const conn = new RTCPeerConnection(ICE_SERVERS);
  conn.onicecandidate = (e) => {
    if (e.candidate && callPeerId != null) {
      sendSignal({ type: 'call_ice', to: callPeerId, candidate: e.candidate });
    }
  };
  conn.ontrack = (e) => {
    $c('remoteVideo').srcObject = e.streams[0];
  };
  conn.onconnectionstatechange = () => {
    if (conn !== pc) return;
    if (conn.connectionState === 'connected') {
      $c('callStatusText').textContent = 'in call';
    }
    if (['disconnected', 'failed', 'closed'].includes(conn.connectionState) && callState !== 'idle') {
      teardownCall();
    }
  };
  return conn;
}

async function startCall(peerId, video) {
  if (callState !== 'idle') { alert('already in a call'); return; }
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

  showCallOverlay('calling', video);
}

async function acceptCall() {
  if (!pendingOffer) return;
  const { from, sdp, video } = pendingOffer;
  pendingOffer = null;
  callPeerId = from;
  callPeerName = users[from] ? users[from].username : 'unknown';
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

  showCallOverlay('active', video);
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
  if (!localStream) return;
  const track = localStream.getAudioTracks()[0];
  if (!track) return;
  track.enabled = !track.enabled;
  $c('muteBtn').textContent = track.enabled ? 'Mute' : 'Unmute';
}

function toggleCamera() {
  if (!localStream) return;
  const track = localStream.getVideoTracks()[0];
  if (!track) return;
  track.enabled = !track.enabled;
  $c('cameraBtn').textContent = track.enabled ? 'Camera off' : 'Camera on';
}

function showCallOverlay(state, video) {
  $c('callOverlay').classList.remove('hidden');
  $c('callPeerName').textContent = callPeerName;
  $c('callStatusText').textContent = state === 'calling' ? 'calling...' : 'in call';
  $c('localVideo').srcObject = localStream;
  $c('videoArea').classList.toggle('audio-only', !video);
  $c('cameraBtn').classList.toggle('hidden', !video);
}

// called from app.js's handleMessage for call_* signal types
function handleCallSignal(data) {
  switch (data.type) {
    case 'call_offer': {
      if (callState !== 'idle') {
        sendSignal({ type: 'call_reject', to: data.from });   // busy
        return;
      }
      pendingOffer = data;
      pendingIce = [];
      callState = 'ringing';
      const caller = users[data.from];
      $c('incomingCallerName').textContent = caller ? caller.username : 'unknown';
      $c('incomingCallType').textContent = data.video ? 'video call' : 'voice call';
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
      const fromCurrentPeer = callPeerId === data.from || (pendingOffer && pendingOffer.from === data.from);
      if (!fromCurrentPeer) break;
      // might arrive while still ringing (no pc yet) or before the
      // remote description lands - buffer instead of dropping
      if (pc && pc.remoteDescription && pc.remoteDescription.type) {
        pc.addIceCandidate(data.candidate).catch(() => {});
      } else {
        pendingIce.push(data.candidate);
      }
      break;
    }
    case 'call_reject': {
      if (callPeerId === data.from) {
        log(`${callPeerName || 'they'} declined the call`);
        teardownCall();
      }
      break;
    }
    case 'call_end': {
      if (callPeerId === data.from) {
        log('call ended');
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