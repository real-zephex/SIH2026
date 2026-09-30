const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');

// Render each frame of the video as a pure function of time, via headless
// Chromium, then hand the PNG sequence to ffmpeg.
const OUT = process.argv[2];
const W = 1920, H = 1080, FPS = 30, DUR = 21.0;
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

  // Fonts must be resolved before any frame is captured, or early frames
  // render with a fallback face.
  await page.evaluate(() => document.fonts.ready);
  await page.waitForTimeout(400);

  const total = Math.round(DUR * FPS);
  const list = ONLY || Array.from({ length: total }, (_, i) => i);

  for (const i of list) {
    const t = i / FPS;
    await page.evaluate((tt) => window.__renderAt(tt), t);
    const name = `f${String(i).padStart(5, '0')}.png`;
    await page.screenshot({ path: path.join(dir, name), type: 'png' });
    if (i % 60 === 0) process.stdout.write(`  frame ${i}/${total}\n`);
  }

  await browser.close();
  console.log(`rendered ${list.length} frames -> ${dir}`);
})();
