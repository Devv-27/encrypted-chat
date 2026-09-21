/*
 * Voice + video calling over WebRTC. The chat messages use our own
 * hand-rolled AES/RSA, but call audio/video does NOT go through that -
 * WebRTC media is encrypted end-to-end automatically by the browser
 * (DTLS-SRTP), so there's nothing to hand-roll here. What this file
 * does is the "signaling": using our existing websocket to pass an
 * SDP offer/answer and ICE candidates between two browsers so they can
 * find each other and set up a direct connection.
 *
 * Fixes vs the earlier version:
 * - ICE candidates that arrive before the peer connection has a remote
 *   description (very common - the caller's candidates start flowing
 *   the instant it calls setLocalDescription, often before the callee
 *   has even clicked Accept) are now queued and flushed once the
 *   remote description is set, instead of being silently dropped.
 * - call_answer now properly awaits setRemoteDescription before
 *   flipping the UI to "active" and before applying queued candidates.
 * - added a public STUN+TURN server pair, not just STUN, so calls can
 *   still connect when both sides are behind strict/symmetric NATs
 *   (STUN alone fails there).
 *
 * Depends on `ws` and `users` being available from app.js.
 */

// NOTE: openrelay.metered.ca's free static-credential TURN server has been
// reported unreliable lately (metered.ca has been pushing people toward an
// API-key-based TURN endpoint instead - see metered.ca/tools/openrelay).
// This matters specifically for the case you're hitting: calls between two
// devices on *different* networks (e.g. phone on mobile data + laptop on
// WiFi) almost always need a working TURN relay, not just STUN - STUN alone
// only helps when a direct/NAT-punched connection is possible, which is
// common on the same WiFi but unreliable across different networks/carriers.
// If calls still fail after this, get a free API key at metered.ca (or
// another TURN provider) and swap the two turn: entries below for the
// credentials it gives you - that's the most likely remaining culprit.
const ICE_SERVERS = {
  iceServers: [
    { urls: 'stun:stun.l.google.com:19302' },
    { urls: 'stun:stun1.l.google.com:19302' },
    { urls: 'stun:global.stun.twilio.com:3478' },
    {
      urls: 'turn:openrelay.metered.ca:80',
      username: 'openrelayproject',
      credential: 'openrelayproject',
    },
    {
      urls: 'turn:openrelay.metered.ca:443',
      username: 'openrelayproject',
      credential: 'openrelayproject',
    },
    {
      urls: 'turn:openrelay.metered.ca:443?transport=tcp',
      username: 'openrelayproject',
      credential: 'openrelayproject',
    },
  ],
};

let pc = null;             // RTCPeerConnection for the active/pending call
let localStream = null;
let callPeerId = null;
let callPeerName = null;
let isVideoCall = false;
let callState = 'idle';    // idle | calling | ringing | active
let pendingOffer = null;
let pendingIceCandidates = []; // candidates that arrived before we had a remote description

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
  pendingIceCandidates = [];
  resetCallUI();
}

function sendSignal(obj) {
  ws.send(JSON.stringify(obj));
}

async function flushPendingIceCandidates() {
  if (!pc) { pendingIceCandidates = []; return; }
  const queued = pendingIceCandidates;
  pendingIceCandidates = [];
  for (const candidate of queued) {
    try { await pc.addIceCandidate(candidate); } catch (e) { /* ignore stale/invalid candidates */ }
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
  pendingOffer = null;

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
  await flushPendingIceCandidates();
  const answer = await pc.createAnswer();
  await pc.setLocalDescription(answer);
  sendSignal({ type: 'call_answer', to: from, sdp: answer.sdp });

  showCallOverlay('active', video);
}

function rejectCall() {
  if (pendingOffer) sendSignal({ type: 'call_reject', to: pendingOffer.from });
  $c('incomingCallModal').classList.add('hidden');
  pendingOffer = null;
  pendingIceCandidates = [];
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
  if (typeof closeSidebar === 'function') closeSidebar();
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
        // busy - auto reject
        sendSignal({ type: 'call_reject', to: data.from });
        return;
      }
      pendingOffer = data;
      pendingIceCandidates = [];
      callState = 'ringing';
      const caller = users[data.from];
      $c('incomingCallerName').textContent = caller ? caller.username : 'unknown';
      $c('incomingCallType').textContent = data.video ? 'video call' : 'voice call';
      if (typeof closeSidebar === 'function') closeSidebar();
      $c('incomingCallModal').classList.remove('hidden');
      break;
    }
    case 'call_answer': {
      if (pc && callPeerId === data.from) {
        (async () => {
          await pc.setRemoteDescription({ type: 'answer', sdp: data.sdp });
          await flushPendingIceCandidates();
          callState = 'active';
          $c('callStatusText').textContent = 'in call';
        })();
      }
      break;
    }
    case 'call_ice': {
      if (!data.candidate) break;
      // is this candidate relevant to the call we're setting up / in?
      const relevant = (callPeerId === data.from) || (pendingOffer && pendingOffer.from === data.from);
      if (!relevant) break;

      if (pc && pc.remoteDescription) {
        pc.addIceCandidate(data.candidate).catch(() => {});
      } else {
        // remote description isn't set yet (still ringing, or the offer
        // hasn't been processed) - hold onto it and apply it once it is
        pendingIceCandidates.push(data.candidate);
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
        pendingIceCandidates = [];
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