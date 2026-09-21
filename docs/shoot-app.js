// Captures the app for the README banner: docs/banner-app-light.png and
// docs/banner-app-dark.png, one per colour scheme.
//
// Start the app first, then run this from the repo root:
//   cargo run --release -- --port 8080
//   node docs/shoot-app.js            # or: node docs/shoot-app.js http://localhost:8080
//
// The demo queue is built here rather than committed: the document pages are drawn on a
// canvas, and the two PDFs are made by posting those pages to the app's own /api/merge.
// So the shot needs no binary fixtures, and the thumbnails in it are real renders of
// real files. The crop is the merge queue itself, the densest, most recognisable part of
// the app, at the app's own layout width (980 px of content plus its gutters).
const fs = require('fs');
const os = require('os');
const path = require('path');
const { chromium } = require('playwright');

const BASE = process.argv[2] || 'http://localhost:8080';
const WIDTH = 1020;
const HEIGHT = 900;
const STRIP = 364; // height of the queue crop the banner shows

/** Draws the demo pages in the page context and hands back data URLs. */
function drawDemoPages() {
  const page = (draw, type = 'image/png') => {
    const c = document.createElement('canvas');
    c.width = 850;
    c.height = 1100;
    const x = c.getContext('2d');
    x.fillStyle = '#ffffff';
    x.fillRect(0, 0, c.width, c.height);
    draw(x, c);
    return c.toDataURL(type, 0.92);
  };
  const line = (x, cx, y, w, h, fill) => {
    x.fillStyle = fill;
    x.fillRect(cx, y, w, h);
  };

  // A statement: banded header, a column of dates and right-aligned amounts.
  const statement = page((x) => {
    line(x, 0, 0, 850, 96, '#1f6f5f');
    line(x, 64, 34, 250, 18, 'rgba(255,255,255,.92)');
    line(x, 64, 62, 150, 10, 'rgba(255,255,255,.55)');
    line(x, 64, 150, 180, 14, '#1d1c19');
    for (let i = 0; i < 16; i++) {
      const y = 200 + i * 48;
      line(x, 64, y, 96, 9, '#cfc8b8');
      line(x, 190, y, 300 - (i % 4) * 46, 9, '#8c877d');
      line(x, 640, y, 146, 9, i % 3 === 0 ? '#a33a2a' : '#5b5852');
      line(x, 64, y + 30, 722, 1, '#e3ded2');
    }
    line(x, 590, 1010, 196, 12, '#1d1c19');
  });

  // An agreement: centred title, paragraphs, two signature rules.
  const agreement = page((x) => {
    line(x, 285, 92, 280, 20, '#1d1c19');
    line(x, 345, 126, 160, 9, '#8c877d');
    for (let block = 0; block < 4; block++) {
      const top = 210 + block * 176;
      line(x, 64, top, 190, 12, '#1d1c19');
      for (let i = 0; i < 6; i++) {
        const w = i === 5 ? 420 : 722 - (i % 3) * 24;
        line(x, 64, top + 34 + i * 20, w, 8, '#b4b1a9');
      }
    }
    line(x, 64, 980, 300, 2, '#5b5852');
    line(x, 450, 980, 300, 2, '#5b5852');
    line(x, 64, 998, 120, 8, '#8c877d');
    line(x, 450, 998, 140, 8, '#8c877d');
  });

  // A photographed ID card, saved as a JPEG like a phone would.
  const photo = page((x, c) => {
    const bg = x.createLinearGradient(0, 0, c.width, c.height);
    bg.addColorStop(0, '#dcd6c6');
    bg.addColorStop(1, '#b9ad95');
    x.fillStyle = bg;
    x.fillRect(0, 0, c.width, c.height);
    x.save();
    x.translate(425, 550);
    x.rotate(-0.04);
    x.fillStyle = '#f7f4ed';
    x.fillRect(-330, -210, 660, 420);
    line(x, -330, -210, 660, 64, '#26455f');
    line(x, -300, -190, 210, 16, 'rgba(255,255,255,.9)');
    line(x, -300, -120, 170, 210, '#cfc8b8');
    line(x, -100, -120, 380, 14, '#5b5852');
    line(x, -100, -86, 300, 14, '#8c877d');
    line(x, -100, -34, 340, 14, '#8c877d');
    line(x, -100, 0, 240, 14, '#8c877d');
    line(x, -300, 130, 580, 10, '#45494f');
    line(x, -300, 152, 520, 10, '#45494f');
    x.restore();
  }, 'image/jpeg');

  return { statement, agreement, photo };
}

function writeDataUrl(dir, name, dataUrl) {
  const file = path.join(dir, name);
  fs.writeFileSync(file, Buffer.from(dataUrl.split(',')[1], 'base64'));
  return file;
}

/** Turns image pages into a PDF using the app's own merge endpoint. */
async function mergeToPdf(pages, outFile) {
  const form = new FormData();
  for (const [i, file] of pages.entries()) {
    const type = file.endsWith('.jpg') ? 'image/jpeg' : 'image/png';
    form.append('file', new Blob([fs.readFileSync(file)], { type }), `page-${i}.png`);
  }
  form.append('manifest', JSON.stringify({ output_name: path.basename(outFile) }));
  const res = await fetch(`${BASE}/api/merge`, { method: 'POST', body: form });
  if (!res.ok) {
    throw new Error(`/api/merge answered ${res.status}: ${await res.text()}`);
  }
  fs.writeFileSync(outFile, Buffer.from(await res.arrayBuffer()));
  return outFile;
}

(async () => {
  const stage = fs.mkdtempSync(path.join(os.tmpdir(), 'cfm-banner-'));
  const browser = await chromium.launch();
  const scratch = await browser.newPage();
  await scratch.goto(BASE);
  const art = await scratch.evaluate(drawDemoPages);
  await scratch.close();

  const statement = writeDataUrl(stage, 'statement.png', art.statement);
  const agreement = writeDataUrl(stage, 'agreement.png', art.agreement);
  const files = [
    await mergeToPdf([statement, statement, statement], path.join(stage, 'bank-statement-january.pdf')),
    await mergeToPdf([agreement, agreement], path.join(stage, 'lease-agreement.pdf')),
    writeDataUrl(stage, 'passport-scan.jpg', art.photo),
  ];

  for (const scheme of ['light', 'dark']) {
    const page = await browser.newPage({
      viewport: { width: WIDTH, height: HEIGHT },
      deviceScaleFactor: 2,
      colorScheme: scheme,
    });
    await page.goto(BASE);
    await page.setInputFiles('#fileInput', files);
    await page.waitForFunction(
      (n) => document.querySelectorAll('li.file').length === n,
      files.length,
    );
    // Wait for every thumbnail to finish rendering.
    await page.waitForFunction(
      (n) => [...document.querySelectorAll('li.file .thumb img')]
        .filter((i) => i.complete && i.naturalWidth).length >= n,
      files.length,
    );
    await page.click('li.file:nth-of-type(3) [data-act=rotate]');
    await page.fill('#outName', 'private-bundle.pdf');
    // Park the pointer clear of the list, or that row keeps its hover highlight.
    await page.mouse.move(6, 6);
    await page.evaluate(() => {
      document.activeElement && document.activeElement.blur();
      // The "Added 3 files" toast would otherwise sit in the middle of the shot.
      const toast = document.getElementById('toast');
      if (toast) toast.classList.remove('on');
    });
    await page.waitForTimeout(500);

    // Crop to the queue: its own top edge down through the file rows, ending inside the
    // settings row so the banner can bleed the rest off its bottom edge.
    const top = await page.evaluate(() => {
      const q = document.querySelector('.queue');
      return q.getBoundingClientRect().top + window.scrollY - 16;
    });
    const out = path.join(__dirname, `banner-app-${scheme}.png`);
    await page.screenshot({ path: out, clip: { x: 0, y: top, width: WIDTH, height: STRIP } });
    console.log('wrote', out);
    await page.close();
  }

  await browser.close();
  fs.rmSync(stage, { recursive: true, force: true });
})().catch((err) => {
  console.error(err);
  process.exit(1);
});
