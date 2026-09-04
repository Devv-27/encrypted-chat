/*
 * Voice + video calling over WebRTC. The chat messages use our own
 * hand-rolled AES/RSA, but call audio/video does NOT go through that -
 * WebRTC media is encrypted end-to-end automatically by the browser
 * (DTLS-SRTP), so there's nothing to hand-roll here. What this file
 * does is the "signaling": using our existing websocket to pass an
 * SDP offer/answer and ICE candidates between two browsers so they can
 * find each other and set up a direct connection.
 *
 * Depends on `ws` and `users` being available from app.js (loaded
 * after app.js in index.html... actually loaded before, see below -
 * we just reference the globals at call time, not at load time).
 */

const ICE_SERVERS = { iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] };

let pc = null;             // RTCPeerConnection for the active/pending call
let localStream = null;
let callPeerId = null;
let callPeerName = null;
let isVideoCall = false;
let callState = 'idle';    // idle | calling | ringing | active

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
  resetCallUI();
}

function sendSignal(obj) {
  ws.send(JSON.stringify(obj));
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

  try {
    localStream = await navigator.mediaDevices.getUserMedia({ audio: true, video });
  } catch (err) {
    alert('could not access microphone/camera: ' + err.message);
    teardownCall();
    return;
  }

  pc = buildPeerConnection();
  localStream.getTracks().forEach(t => pc.addTrack(t, localStream));

  const offer = await pc.createOffer();
  await pc.setLocalDescription(offer);
  sendSignal({ type: 'call_offer', to: peerId, sdp: offer.sdp, video });

  showCallOverlay('calling', video);
}

async function acceptCall() {
  const { from, sdp, video } = pendingOffer;
  callPeerId = from;
  callPeerName = users[from] ? users[from].username : 'unknown';
  isVideoCall = video;
  callState = 'active';
  $c('incomingCallModal').classList.add('hidden');

  try {
    localStream = await navigator.mediaDevices.getUserMedia({ audio: true, video });
  } catch (err) {
    alert('could not access microphone/camera: ' + err.message);
    sendSignal({ type: 'call_reject', to: from });
    teardownCall();
    return;
  }

  pc = buildPeerConnection();
  localStream.getTracks().forEach(t => pc.addTrack(t, localStream));
  await pc.setRemoteDescription({ type: 'offer', sdp });
  const answer = await pc.createAnswer();
  await pc.setLocalDescription(answer);
  sendSignal({ type: 'call_answer', to: from, sdp: answer.sdp });

  showCallOverlay('active', video);
}

function rejectCall() {
  if (pendingOffer) sendSignal({ type: 'call_reject', to: pendingOffer.from });
  $c('incomingCallModal').classList.add('hidden');
  pendingOffer = null;
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

let pendingOffer = null;

// called from app.js's handleMessage for call_* signal types
function handleCallSignal(data) {
  switch (data.type) {
    case 'call_offer': {
      if (callState !== 'idle') {
        // busy - auto reject
        sendSignal({ type: 'call_reject', to: data.from });
        return;
      }
      pendingOffer = data;
      callState = 'ringing';
      const caller = users[data.from];
      $c('incomingCallerName').textContent = caller ? caller.username : 'unknown';
      $c('incomingCallType').textContent = data.video ? 'video call' : 'voice call';
      $c('incomingCallModal').classList.remove('hidden');
      break;
    }
    case 'call_answer': {
      if (pc && callPeerId === data.from) {
        pc.setRemoteDescription({ type: 'answer', sdp: data.sdp });
        callState = 'active';
        $c('callStatusText').textContent = 'in call';
      }
      break;
    }
    case 'call_ice': {
      if (pc && callPeerId === data.from && data.candidate) {
        pc.addIceCandidate(data.candidate).catch(() => {});
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
