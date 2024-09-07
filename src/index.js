#!/usr/bin/env node

const yargs = require('yargs');
const scanStringInputSanitization = require('./stringSanitization');
const scanCorsConfiguration = require('./corsConfig');
const scanAuthentication = require('./authentication');
const scanAuthorization = require('./authorization');
const generateReport = require('./reportGenerator');

const argv = yargs
    .option('all', {
        alias: 'a',
        description: 'Run all scans',
        type: 'boolean',
    })
    .option('string-sanitization', {
        alias: 's',
        description: 'Check string input sanitization',
        type: 'boolean',
    })
    .option('cors', {
        alias: 'c',
        description: 'Check CORS configuration',
        type: 'boolean',
    })
    .option('authentication', {
        alias: 'u',
        description: 'Check authentication implementation',
        type: 'boolean',
    })
    .option('authorization', {
        alias: 'z',
        description: 'Check authorization setup',
        type: 'boolean',
    })
    .option('html-report', {
        alias: 'h',
        description: 'Generate HTML report',
        type: 'boolean',
    })
    .help()
    .alias('help', 'h')
    .argv;

async function scanRepository(repoPath, options) {
    const results = {};

    if (options.all || options.stringSanitization) {
        results.stringSanitization = await scanStringInputSanitization(repoPath);
    }
    if (options.all || options.cors) {
        results.corsConfiguration = await scanCorsConfiguration(repoPath);
    }
    if (options.all || options.authentication) {
        results.authentication = await scanAuthentication(repoPath);
    }
    if (options.all || options.authorization) {
        results.authorization = await scanAuthorization(repoPath);
    }

    // Generate and display terminal report
    const terminalReport = generateReport(results, 'terminal');
    console.log(terminalReport);

    // Generate and save HTML report if requested
    if (options.htmlReport) {
        const htmlReport = generateReport(results, 'html');
        fs.writeFileSync(path.join(repoPath, 'security_report.html'), htmlReport);
        console.log('HTML report saved as security_report.html');
    }
}

// Run the scanner
const repoPath = process.cwd();
scanRepository(repoPath, argv);