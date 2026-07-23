/*
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
*/

const workflow = {
  publish: {
    title: "Publish an image",
    body: "The operator publishes one IOS-XE image. IRIS records the hashes and creates private swarm metadata for the fleet.",
    command: "iris-publish /opt/images/iosxe/c9300/<image>.bin",
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
    body: "The agent checks the downloaded file and IOS verifies the staged copy before IRIS reports success.",
    command: "copy /verify <staged-file> flash:<image>.bin",
  },
  report: {
    title: "Report staged and stop",
    body: "The device reports that the image is staged. IRIS does not install, activate, change boot variables, or reload.",
    command: "GET https://<server-ip>:8443/v1/catalog",
  },
};

const paths = {
  guest: {
    title: "Catalyst 9300 Guest Shell",
    copy: "Generate a per-device installer, bootstrap Guest Shell, and let EEM keep the staging agent alive.",
    items: [
      "Installs catalog trust material.",
      "Downloads image pieces through the private swarm.",
      "Stages approved images to `flash:`.",
    ],
  },
  iox: {
    title: "IE-3x00 and IE-3400 IOx",
    copy: "Package the same staging model as an IOx Docker app and use SSH-to-self for IOS copy and verify commands.",
    items: [
      "Serves operator-built `iris-arm64.tar` from artifacts.",
      "Downloads image pieces through the private swarm.",
      "Stages approved images to `sdflash:`.",
    ],
  },
  server: {
    title: "Server and console",
    copy: "Run the catalog, private tracker, initial seeder, artifact server, console, telemetry, and encrypted state store.",
    items: [
      "Introduces image metadata and private torrents.",
      "Keeps aria2 RPC local-only.",
      "Exposes fleet progress in the console.",
    ],
  },
};

function setActive(buttons, current) {
  buttons.forEach((button) => {
    const active = button === current;
    button.classList.toggle("active", active);
    button.setAttribute("aria-selected", active ? "true" : "false");
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

function initCopies() {
  document.querySelectorAll("[data-copy-target]").forEach((button) => {
    button.addEventListener("click", async () => {
      const target = document.getElementById(button.dataset.copyTarget);
      const text = target?.textContent.trim();
      if (!text) return;

      try {
        await navigator.clipboard.writeText(text);
        button.textContent = "Copied";
        window.setTimeout(() => {
          button.textContent = "Copy";
        }, 1200);
      } catch {
        button.textContent = "Select text";
      }
    });
  });
}

function initWorkflow() {
  const buttons = Array.from(document.querySelectorAll(".step"));
  const title = document.getElementById("flow-title");
  const body = document.getElementById("flow-body");
  const command = document.getElementById("flow-command");

  buttons.forEach((button) => {
    button.addEventListener("click", () => {
      const detail = workflow[button.dataset.step];
      if (!detail) return;
      setActive(buttons, button);
      title.textContent = detail.title;
      body.textContent = detail.body;
      command.textContent = detail.command;
    });
  });
}

function initPaths() {
  const buttons = Array.from(document.querySelectorAll(".path-tab"));
  const title = document.getElementById("path-title");
  const copy = document.getElementById("path-copy");
  const list = document.getElementById("path-list");

  buttons.forEach((button) => {
    button.addEventListener("click", () => {
      const detail = paths[button.dataset.path];
      if (!detail) return;
      setActive(buttons, button);
      title.textContent = detail.title;
      copy.textContent = detail.copy;
      list.replaceChildren(
        ...detail.items.map((item) => {
          const li = document.createElement("li");
          li.textContent = item;
          return li;
        }),
      );
    });
  });
}

function initFilters() {
  const buttons = Array.from(document.querySelectorAll(".filter"));
  const rows = Array.from(document.querySelectorAll("tbody tr[data-scope]"));

  buttons.forEach((button) => {
    button.addEventListener("click", () => {
      setActive(buttons, button);
      const filter = button.dataset.filter;
      rows.forEach((row) => {
        row.hidden = filter !== "all" && row.dataset.scope !== filter;
      });
    });
  });
}

function initCanvas() {
  const canvas = document.getElementById("swarm-canvas");
  const context = canvas.getContext("2d");
  const particles = [];
  const count = 52;

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

    window.requestAnimationFrame(draw);
  }

  resize();
  seed();
  draw();

  window.addEventListener("resize", () => {
    resize();
    seed();
  });
}

initHeader();
initCopies();
initWorkflow();
initPaths();
initFilters();
initCanvas();
