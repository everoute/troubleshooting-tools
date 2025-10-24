const { chromium } = require('playwright');
const path = require('path');

async function convertHtmlToPdf() {
    const browser = await chromium.launch();
    const page = await browser.newPage();

    const htmlPath = path.resolve(__dirname, 'network-troubleshooting-tools-demo-report.html');
    const pdfPath = path.resolve(__dirname, 'network-troubleshooting-tools-demo-report.pdf');

    // Load HTML file
    await page.goto(`file://${htmlPath}`, { waitUntil: 'networkidle' });

    // Generate PDF
    await page.pdf({
        path: pdfPath,
        format: 'A4',
        margin: {
            top: '2cm',
            right: '2cm',
            bottom: '2cm',
            left: '2cm'
        },
        printBackground: true,
        displayHeaderFooter: true,
        headerTemplate: '<div></div>',
        footerTemplate: `
            <div style="font-size: 9pt; color: #666; width: 100%; text-align: center; padding: 5px;">
                <span class="pageNumber"></span> / <span class="totalPages"></span>
            </div>
        `
    });

    await browser.close();
    console.log(`PDF generated successfully: ${pdfPath}`);
}

convertHtmlToPdf().catch(console.error);
