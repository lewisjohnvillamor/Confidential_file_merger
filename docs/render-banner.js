// Renders docs/banner.html to docs/banner-light.png and docs/banner-dark.png.
//
// The banner is laid out at 1280 CSS px and the README shows it 840 px wide, so it is
// rasterised at 1.3125x: exactly 2x the displayed size, which is what a HiDPI screen
// needs and no more. omitBackground keeps the rounded corners transparent, so the card
// sits on GitHub's light and dark page backgrounds alike.
// Needs Playwright's Chromium: npx playwright install chromium (once), then:
//   node docs/render-banner.js
const path = require('path');
const { chromium } = require('playwright');

(async () => {
  const source = 'file://' + path.join(__dirname, 'banner.html');
  const browser = await chromium.launch();
  for (const scheme of ['light', 'dark']) {
    const page = await browser.newPage({
      viewport: { width: 1280, height: 360 },
      deviceScaleFactor: 1.3125,
      colorScheme: scheme,
    });
    await page.goto(source);
    await page.waitForTimeout(150);
    const out = path.join(__dirname, `banner-${scheme}.png`);
    await page.locator('.banner').screenshot({ path: out, omitBackground: true });
    console.log('wrote', out);
    await page.close();
  }
  await browser.close();
})().catch((err) => {
  console.error(err);
  process.exit(1);
});
