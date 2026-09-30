// Render every frame of the walkthrough as a pure function of time, via
// headless Chromium, then hand the PNG sequence to ffmpeg.
//
//   node shoot.js <outDir>            # all frames
//   node shoot.js <outDir> 0,150,300  # only these frame indices (for still review)
//
// playwright is resolved from PLAYWRIGHT_ROOT (default /tmp/opencode) so this
// script needs no local node_modules.
const path0 = require('path');
const PW_ROOT = process.env.PLAYWRIGHT_ROOT || '/tmp/opencode';
const { chromium } = require(path0.join(PW_ROOT, 'node_modules', 'playwright'));
const fs = require('fs');
const path = require('path');

const OUT = process.argv[2];
const W = 1920, H = 1080, FPS = 30, DUR = 268.0;
const ONLY = process.argv[3] ? process.argv[3].split(',').map(Number) : null;

(async () => {
  const dir = path.join(OUT, 'work', 'frames');
  fs.mkdirSync(dir, { recursive: true });

  const browser = await chromium.launch({
    args: ['--force-color-profile=srgb', '--font-render-hinting=none',
           '--disable-lcd-text', '--hide-scrollbars'],
  });
  const page = await browser.newPage({
    viewport: { width: W, height: H },
    deviceScaleFactor: 1,
  });

  const file = 'file://' + path.join(OUT, 'work', 'frame.html');
  await page.goto(file, { waitUntil: 'load' });

  // Any layout or script error here means a black frame later — fail loudly.
  const errs = [];
  page.on('pageerror', e => errs.push(String(e)));
  page.on('console', m => { if (m.type() === 'error') errs.push(m.text()); });

  // Fonts must be resolved before any frame is captured, or early frames
  // render with a fallback face.
  await page.evaluate(() => document.fonts.ready);
  await page.waitForTimeout(500);

  if (errs.length) { console.error('PAGE ERRORS:\n' + errs.join('\n')); }

  const total = Math.round(DUR * FPS);
  const list = ONLY || Array.from({ length: total }, (_, i) => i);
  const t0 = Date.now();

  for (const i of list) {
    const t = i / FPS;
    await page.evaluate((tt) => window.__renderAt(tt), t);
    const name = `f${String(i).padStart(5, '0')}.png`;
    await page.screenshot({ path: path.join(dir, name), type: 'png' });
    if (i % 300 === 0) {
      const el = (Date.now() - t0) / 1000;
      const rate = i > 0 ? (i / el).toFixed(1) : '0';
      console.log(`  frame ${i}/${total}  ${el.toFixed(0)}s elapsed  ${rate} fps`);
    }
  }

  await browser.close();
  if (errs.length) { console.error('PAGE ERRORS:\n' + errs.join('\n')); process.exit(1); }
  console.log(`rendered ${list.length} frames -> ${dir}`);
})();
