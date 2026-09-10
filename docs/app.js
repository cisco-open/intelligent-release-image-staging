/*
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
*/

const workflow = {
  publish: {
    title: "Publish an image",
    body: "The operator publishes one Cisco image or patch. IRIS records the hashes and creates private swarm metadata for the fleet.",
    command: "iris-publish /opt/images/<image>.bin",
  },
  assign: {
    title: "Choose who should stage it",
    body: "A simple assignment maps each device to the approved image. The device agent picks up that intent on its next catalog poll.",
    command: "tools/apply-assignments.sh fleet/assignments.csv",
  },
  download: {
    title: "Share image pieces",
    body: "Each device downloads missing pieces from the IRIS server and from other devices that already have those pieces.",
    command: "private torrent + aria2c piece download",
  },
  verify: {
    title: "Verify on the device",
    body: "The agent checks the downloaded file's SHA-256 against the catalog. IOS-XE then copies it to the target filesystem and checks its size; XR stages it directly on harddisk:.",
    command: "SHA-256 check → platform storage → staged heartbeat",
  },
  report: {
    title: "Report staged",
    body: "The device reports that the image is staged and can keep seeding while assigned. IRIS does not install, activate, change boot variables, or reload.",
    command: "POST https://<server-ip>:8443/v1/devices/<device>/heartbeat",
  },
};

const paths = {
  guest: {
    title: "Catalyst 9000 Guest Shell",
    copy: "Run the shared agent in Guest Shell, supervised by EEM, or use the amd64 IOx container on supported switches with app-hosting storage.",
    items: [
      "Installs catalog trust material.",
      "Downloads image pieces through the private swarm.",
      "Stages approved images to device storage.",
    ],
  },
  iox: {
    title: "Industrial Ethernet IOx",
    copy: "Run the shared IOx/XR device image as an IOx app. The agent uses SSH-to-self for IOS file placement.",
    items: [
      "Receives iris-arm64.tar over SCP during onboarding.",
      "Downloads image pieces through the private swarm.",
      "Stages approved images to device storage.",
    ],
  },
  router: {
    title: "Catalyst 8000",
    copy: "Run the shared agent in Guest Shell or as an IOx app through a routed or NAT VirtualPortGroup.",
    items: [
      "Checks device prerequisites before onboarding.",
      "Downloads image pieces through the private swarm.",
      "Stages approved images to device storage.",
    ],
  },
  server: {
    title: "Server and Console",
    copy: "Run the server and browser Console on one Docker host, separate Docker hosts, or Kubernetes. The Console calls the server over authenticated HTTPS.",
    items: [
      "The server stores images and state and seeds the swarm.",
      "The Console serves the UI without mounting server data.",
      "Devices contact the server's catalog and tracker directly.",
    ],
  },
  xr: {
    title: "Cisco 8000 Series appmgr",
    copy: "Run the shared IOx/XR device image under appmgr, using the router's network and harddisk: storage.",
    items: [
      "Receives iris-xr.rpm over SCP during onboarding.",
      "Downloads image pieces through the private swarm directly onto harddisk:.",
      "Stages the software but does not install, activate, or reload the device.",
    ],
  },
};

function setActive(buttons, current) {
  buttons.forEach((button) => {
    const active = button === current;
    button.classList.toggle("active", active);
    button.setAttribute("aria-selected", active ? "true" : "false");
    // Roving tabindex: only the selected tab is in the page's tab order, and
    // Left/Right moves between tabs. Declaring role="tab" without this sets an
    // expectation assistive technology announces ("tab, 1 of 5") and the page
    // would not honour.
    button.tabIndex = active ? 0 : -1;
  });
}

// Arrow-key navigation for one tablist, per the ARIA tabs pattern: Left/Right
// wrap, Home/End jump to the ends, and activation follows focus (these tabs
// swap an inline panel, so there is nothing expensive to defer).
function bindTablistKeys(buttons, activate) {
  buttons.forEach((button, index) => {
    button.addEventListener("keydown", (event) => {
      const last = buttons.length - 1;
      let next = null;
      if (event.key === "ArrowRight") next = index === last ? 0 : index + 1;
      else if (event.key === "ArrowLeft") next = index === 0 ? last : index - 1;
      else if (event.key === "Home") next = 0;
      else if (event.key === "End") next = last;
      if (next === null) return;
      event.preventDefault();
      buttons[next].focus();
      activate(buttons[next]);
    });
  });
}

function initHeader() {
  const header = document.querySelector(".site-header");
  const update = () => {
    header.dataset.elevated = window.scrollY > 24 ? "true" : "false";
  };
  update();
  window.addEventListener("scroll", update, { passive: true });
}

function initWorkflow() {
  const buttons = Array.from(document.querySelectorAll(".step"));
  const title = document.getElementById("flow-title");
  const body = document.getElementById("flow-body");
  const command = document.getElementById("flow-command");

  const panel = document.getElementById("flow-detail");

  const activate = (button) => {
    const detail = workflow[button.dataset.step];
    if (!detail) return;
    setActive(buttons, button);
    // One panel serves all five tabs, so its label follows the selected tab.
    if (panel && button.id) panel.setAttribute("aria-labelledby", button.id);
    title.textContent = detail.title;
    body.textContent = detail.body;
    command.textContent = detail.command;
  };

  buttons.forEach((button) => {
    button.addEventListener("click", () => activate(button));
  });
  bindTablistKeys(buttons, activate);
  const initial = buttons.find((b) => b.classList.contains("active"));
  if (initial) activate(initial);
}

function initPaths() {
  const buttons = Array.from(document.querySelectorAll(".path-tab"));
  const title = document.getElementById("path-title");
  const copy = document.getElementById("path-copy");
  const list = document.getElementById("path-list");

  const panel = document.getElementById("path-body");

  const activate = (button) => {
    const detail = paths[button.dataset.path];
    if (!detail) return;
    setActive(buttons, button);
    if (panel && button.id) panel.setAttribute("aria-labelledby", button.id);
    title.textContent = detail.title;
    copy.textContent = detail.copy;
    list.replaceChildren(
      ...detail.items.map((item) => {
        const li = document.createElement("li");
        li.textContent = item;
        return li;
      }),
    );
  };

  buttons.forEach((button) => {
    button.addEventListener("click", () => activate(button));
  });
  bindTablistKeys(buttons, activate);

  // IRIS-17-007: the default tab's bullets are ALSO in index.html, and the two
  // copies had drifted (the markup said "Runs the agent every 60 seconds", this
  // object says "Downloads image pieces through the private swarm"), so
  // returning to the default tab silently rewrote a bullet. Render the default
  // from this object on load so there is one source of truth.
  const initial = buttons.find((b) => b.classList.contains("active"));
  if (initial) activate(initial);
}


const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");

function initCanvas() {
  const canvas = document.getElementById("swarm-canvas");
  const context = canvas.getContext("2d");
  const particles = [];
  const count = 52;
  let stopped = reducedMotion.matches;

  function resize() {
    const scale = window.devicePixelRatio || 1;
    canvas.width = Math.floor(window.innerWidth * scale);
    canvas.height = Math.floor(window.innerHeight * scale);
    canvas.style.width = `${window.innerWidth}px`;
    canvas.style.height = `${window.innerHeight}px`;
    context.setTransform(scale, 0, 0, scale, 0, 0);
  }

  function seed() {
    particles.length = 0;
    for (let index = 0; index < count; index += 1) {
      particles.push({
        x: Math.random() * window.innerWidth,
        y: Math.random() * window.innerHeight,
        vx: (Math.random() - 0.5) * 0.32,
        vy: (Math.random() - 0.5) * 0.32,
        r: 1.6 + Math.random() * 2.6,
      });
    }
  }

  function draw() {
    context.clearRect(0, 0, window.innerWidth, window.innerHeight);

    for (const particle of particles) {
      particle.x += particle.vx;
      particle.y += particle.vy;

      if (particle.x < -10) particle.x = window.innerWidth + 10;
      if (particle.x > window.innerWidth + 10) particle.x = -10;
      if (particle.y < -10) particle.y = window.innerHeight + 10;
      if (particle.y > window.innerHeight + 10) particle.y = -10;
    }

    for (let a = 0; a < particles.length; a += 1) {
      for (let b = a + 1; b < particles.length; b += 1) {
        const p1 = particles[a];
        const p2 = particles[b];
        const dx = p1.x - p2.x;
        const dy = p1.y - p2.y;
        const distance = Math.hypot(dx, dy);
        if (distance < 150) {
          context.globalAlpha = (150 - distance) / 280;
          context.strokeStyle = "#88ff00";
          context.lineWidth = 1;
          context.beginPath();
          context.moveTo(p1.x, p1.y);
          context.lineTo(p2.x, p2.y);
          context.stroke();
        }
      }
    }

    context.globalAlpha = 1;
    for (const particle of particles) {
      context.fillStyle = particle.x > window.innerWidth * 0.42 ? "#88ff00" : "#bd63ff";
      context.beginPath();
      context.arc(particle.x, particle.y, particle.r, 0, Math.PI * 2);
      context.fill();
    }

    if (!stopped) window.requestAnimationFrame(draw);
  }

  resize();
  seed();
  // Runs once either way: with reduced motion on, `stopped` keeps it from
  // re-arming, so the viewer gets a still frame rather than a blank canvas.
  draw();

  window.addEventListener("resize", () => {
    resize();
    seed();
  });

  // WCAG 2.2 SC 2.2.2 (Pause, Stop, Hide, Level A): this is full-viewport
  // motion that starts automatically, runs indefinitely, and sits alongside
  // other content, so it must stop when the viewer asks for reduced motion.
  // The rAF loop checks `stopped` before re-arming, and the listener means a
  // viewer who flips the OS setting with the page open sees it take effect.
  reducedMotion.addEventListener("change", (event) => {
    if (event.matches) {
      stopped = true;
      context.clearRect(0, 0, window.innerWidth, window.innerHeight);
    } else if (stopped) {
      stopped = false;
      draw();
    }
  });
}

initHeader();
initWorkflow();
initPaths();
initCanvas();
