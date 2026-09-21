/*
 * Protected image viewer.
 *
 * A photo here is never turned into a URL,
 * so there is nothing to "save image as",
 * copy the address of, or drag to the desktop.
 *
 * The decrypted bytes are decoded into a bitmap,
 * painted onto a canvas, and then overwritten
 * with zeros.
 *
 * Closing the viewer clears the canvas too.
 *
 * What this stops:
 * - right-click save
 * - drag-out
 * - long-press save on phones
 * - Ctrl/Cmd+S
 * - printing
 * - leaving the photo sitting on screen while
 *   switching tabs
 *
 * A faint watermark with the viewer's name
 * and time is painted into the pixels.
 *
 * What no web page can stop:
 * - OS screenshot
 * - screen recording
 * - another phone pointed at the screen
 * - someone reading the canvas from devtools
 */

async function openProtectedImage({
  bytes,
  mime,
  viewer,
  title,
  note,
  onClose
}) {
  let bitmap;

  try {
    bitmap = await createImageBitmap(
      new Blob(
        [bytes],
        {
          type: mime || 'image/jpeg'
        }
      )
    );
  } catch {
    bytes.fill(0);

    toast(
      'That photo could not be displayed'
    );

    if (onClose) {
      onClose(false);
    }

    return null;
  }

  /*
   * Clear decrypted byte buffer after
   * creating the bitmap.
   */
  bytes.fill(0);

  const overlay =
    document.createElement('div');

  overlay.className = 'pv';

  overlay.setAttribute(
    'role',
    'dialog'
  );

  overlay.setAttribute(
    'aria-label',
    'Private photo'
  );

  overlay.innerHTML =
    '<div class="pv-bar">' +

      '<div class="pv-title">' +
        '<strong></strong>' +
        '<span></span>' +
      '</div>' +

      '<button type="button" class="pv-close">' +
        'Close' +
      '</button>' +

    '</div>' +

    '<div class="pv-stage">' +

      '<canvas class="pv-canvas" ' +
        'draggable="false">' +
      '</canvas>' +

      '<div class="pv-cover hidden">' +
        'Hidden while this window is in the background' +
      '</div>' +

    '</div>' +

    '<p class="pv-foot"></p>';

  /*
   * Set title and note safely using textContent.
   */

  overlay.querySelector(
    '.pv-title strong'
  ).textContent =
    title || 'Photo';

  overlay.querySelector(
    '.pv-title span'
  ).textContent =
    note || '';

  overlay.querySelector(
    '.pv-foot'
  ).textContent =
    'No download, no copy. The photo is wiped from this tab when you close it.';

  const canvas =
    overlay.querySelector(
      'canvas'
    );

  const cover =
    overlay.querySelector(
      '.pv-cover'
    );

  document.body.appendChild(
    overlay
  );

  document.body.classList.add(
    'pv-open'
  );

  /*
   * Draw the image and watermark.
   */

  function paint() {
    const dpr =
      Math.min(
        window.devicePixelRatio || 1,
        2
      );

    const maxW =
      Math.min(
        window.innerWidth - 24,
        1400
      );

    const maxH =
      window.innerHeight - 150;

    const scale =
      Math.min(
        maxW / bitmap.width,
        maxH / bitmap.height,
        1
      );

    const w =
      Math.max(
        1,
        Math.round(
          bitmap.width * scale
        )
      );

    const h =
      Math.max(
        1,
        Math.round(
          bitmap.height * scale
        )
      );

    canvas.width =
      w * dpr;

    canvas.height =
      h * dpr;

    canvas.style.width =
      w + 'px';

    canvas.style.height =
      h + 'px';

    const ctx =
      canvas.getContext('2d');

    ctx.drawImage(
      bitmap,
      0,
      0,
      canvas.width,
      canvas.height
    );

    /*
     * Watermark:
     * viewer name + current date/time.
     */

    const stamp =
      `${viewer} · ${
        new Date().toLocaleString(
          [],
          {
            day: 'numeric',
            month: 'short',
            hour: '2-digit',
            minute: '2-digit'
          }
        )
      }`;

    const fs =
      Math.max(
        12,
        Math.round(
          canvas.width / 30
        )
      );

    ctx.save();

    ctx.font =
      `600 ${fs}px "Bricolage Grotesque", system-ui, sans-serif`;

    ctx.textBaseline =
      'middle';

    ctx.rotate(
      -Math.PI / 7
    );

    const stepX =
      ctx.measureText(stamp).width +
      fs * 3;

    const stepY =
      fs * 4.2;

    const reach =
      Math.hypot(
        canvas.width,
        canvas.height
      );

    for (
      let y = -reach;
      y < reach;
      y += stepY
    ) {
      for (
        let x = -reach;
        x < reach;
        x += stepX
      ) {
        ctx.lineWidth =
          Math.max(
            2,
            fs / 7
          );

        ctx.strokeStyle =
          'rgba(0,0,0,0.22)';

        ctx.strokeText(
          stamp,
          x,
          y
        );

        ctx.fillStyle =
          'rgba(255,255,255,0.30)';

        ctx.fillText(
          stamp,
          x,
          y
        );
      }
    }

    ctx.restore();
  }

  paint();

  let closed = false;

  /*
   * Hide photo when window loses focus.
   */

  const hide = () => {
    canvas.style.visibility =
      'hidden';

    cover.classList.remove(
      'hidden'
    );
  };

  const show = () => {
    if (document.hasFocus()) {
      canvas.style.visibility =
        '';

      cover.classList.add(
        'hidden'
      );
    }
  };

  /*
   * Close viewer and wipe canvas.
   */

  function close() {
    if (closed) return;

    closed = true;

    window.removeEventListener(
      'blur',
      hide
    );

    window.removeEventListener(
      'focus',
      show
    );

    document.removeEventListener(
      'visibilitychange',
      onVisibility
    );

    document.removeEventListener(
      'keydown',
      onKey,
      true
    );

    /*
     * Clear canvas.
     */

    canvas
      .getContext('2d')
      .clearRect(
        0,
        0,
        canvas.width,
        canvas.height
      );

    canvas.width =
      canvas.height =
      0;

    bitmap.close();

    overlay.remove();

    document.body.classList.remove(
      'pv-open'
    );

    if (onClose) {
      onClose(true);
    }
  }

  /*
   * Hide photo when tab becomes hidden.
   */

  function onVisibility() {
    document.hidden
      ? hide()
      : show();
  }

  /*
   * Keyboard protection.
   */

  function onKey(e) {
    if (e.key === 'Escape') {
      e.preventDefault();
      close();
      return;
    }

    const mod =
      e.ctrlKey ||
      e.metaKey;

    /*
     * PrintScreen:
     * hide image temporarily.
     */

    if (e.key === 'PrintScreen') {
      hide();

      try {
        navigator.clipboard.writeText('');
      } catch {
        /* ignore */
      }

      setTimeout(
        show,
        1200
      );
    }

    /*
     * Block:
     * Ctrl/Cmd + S
     * Ctrl/Cmd + P
     * Ctrl/Cmd + C
     * Ctrl/Cmd + A
     * Ctrl/Cmd + U
     */

    if (
      mod &&
      [
        's',
        'p',
        'c',
        'a',
        'u'
      ].includes(
        e.key.toLowerCase()
      )
    ) {
      e.preventDefault();
    }
  }

  /*
   * Window focus/visibility handlers.
   */

  window.addEventListener(
    'blur',
    hide
  );

  window.addEventListener(
    'focus',
    show
  );

  document.addEventListener(
    'visibilitychange',
    onVisibility
  );

  document.addEventListener(
    'keydown',
    onKey,
    true
  );

  /*
   * Prevent context menu,
   * dragging and copying.
   */

  [
    'contextmenu',
    'dragstart',
    'copy',
    'cut'
  ].forEach(ev => {
    overlay.addEventListener(
      ev,
      e => e.preventDefault()
    );
  });

  /*
   * Close button.
   */

  overlay
    .querySelector('.pv-close')
    .addEventListener(
      'click',
      close
    );

  overlay
    .querySelector('.pv-close')
    .focus();

  return close;
}