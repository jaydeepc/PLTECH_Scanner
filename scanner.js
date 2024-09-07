const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const cheerio = require('cheerio');

const scanStringInputSanitization = require('./modules/stringSanitization');
const scanCorsConfiguration = require('./modules/corsConfig');
const scanAuthentication = require('./modules/authentication');
const scanAuthorization = require('./modules/authorization');
const generateReport = require('./modules/reportGenerator');

async function scanRepository(repoPath) {
    const results = {
        stringSanitization: await scanStringInputSanitization(repoPath),
        corsConfiguration: await scanCorsConfiguration(repoPath),
        authentication: await scanAuthentication(repoPath),
        authorization: await scanAuthorization(repoPath)
    };

    // Generate and display terminal report
    const terminalReport = generateReport(results, 'terminal');
    console.log(terminalReport);

    // Generate and save HTML report
    const htmlReport = generateReport(results, 'html');
    fs.writeFileSync(path.join(repoPath, 'security_report.html'), htmlReport);
    console.log('HTML report saved as security_report.html');
}

// Run the scanner
const repoPath = process.cwd();
scanRepository(repoPath);