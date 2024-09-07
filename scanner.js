#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const chalk = require('chalk');
const yargs = require('yargs/yargs');
const { hideBin } = require('yargs/helpers');

const scanStringInputSanitization = require('./src/stringSanitization');
const scanCorsConfiguration = require('./src/corsConfig');
const scanAuthentication = require('./src/authentication');
const scanAuthorization = require('./src/authorization');
const generateReport = require('./src/reportGenerator');

async function determineLanguages(repoPath) {
    const languages = new Set();
    const files = await getFiles(repoPath);

    files.forEach(file => {
        const ext = path.extname(file).toLowerCase();
        switch (ext) {
            case '.js':
            case '.jsx':
            case '.ts':
            case '.tsx':
                languages.add('JavaScript');
                break;
            case '.py':
                languages.add('Python');
                break;
            case '.php':
                languages.add('PHP');
                break;
            case '.java':
                languages.add('Java');
                break;
        }
    });

    return Array.from(languages);
}

async function getFiles(dir) {
    const dirents = await fs.promises.readdir(dir, { withFileTypes: true });
    const files = await Promise.all(dirents.map((dirent) => {
        const res = path.resolve(dir, dirent.name);
        return dirent.isDirectory() ? getFiles(res) : res;
    }));
    return Array.prototype.concat(...files).filter(file => !shouldIgnoreFile(file));
}

function shouldIgnoreFile(file) {
    const ignoreDirs = [
        'node_modules',
        'lib',
        'vendor',
        'dist',
        'build',
        '.venv',
        'venv',
        'env',
        '__pycache__',
        '.git'
    ];
    return ignoreDirs.some(dir => file.includes(dir));
}

async function scanRepository(repoPath, options) {
    console.log(chalk.blue('Starting security scan...\n'));

    const languages = await determineLanguages(repoPath);
    console.log(chalk.yellow(`Languages detected: ${languages.join(', ')}\n`));

    const results = {};
    const jsonReport = {};

    try {
        if (options.all || options.string) {
            console.log(chalk.yellow('Scanning for string input sanitization issues...'));
            results.stringSanitization = await scanStringInputSanitization(repoPath);
            if (!results.stringSanitization.noRelevantFiles) {
                jsonReport.stringSanitization = generateJsonReport(results.stringSanitization);
            }
        }
        if (options.all || options.cors) {
            console.log(chalk.yellow('Scanning for CORS configuration issues...'));
            results.corsConfiguration = await scanCorsConfiguration(repoPath);
            if (!results.corsConfiguration.noRelevantFiles) {
                jsonReport.corsConfiguration = generateJsonReport(results.corsConfiguration);
            }
        }
        if (options.all || options.auth) {
            console.log(chalk.yellow('Scanning for authentication issues...'));
            results.authentication = await scanAuthentication(repoPath);
            if (!results.authentication.noRelevantFiles) {
                jsonReport.authentication = generateJsonReport(results.authentication);
            }
        }
        if (options.all || options.authz) {
            console.log(chalk.yellow('Scanning for authorization issues...'));
            results.authorization = await scanAuthorization(repoPath);
            if (!results.authorization.noRelevantFiles) {
                jsonReport.authorization = generateJsonReport(results.authorization);
            }
        }

        // Check if any scans were performed
        const scansPerformed = Object.keys(results).length > 0;

        if (!scansPerformed) {
            console.log(chalk.yellow('No scans were performed. Please specify at least one scan type or use --all.'));
            process.exit(0);
        }

        // Generate and display terminal report
        const terminalReport = generateReport(results, 'terminal');
        console.log(terminalReport);

        // Generate and save HTML report
        const htmlReport = generateReport(results, 'html');
        const reportDir = path.join(repoPath, 'security_report');
        fs.mkdirSync(reportDir, { recursive: true });
        const htmlReportPath = path.join(reportDir, 'report.html');
        fs.writeFileSync(htmlReportPath, htmlReport);
        console.log(chalk.green(`HTML report saved as ${htmlReportPath}`));

        // Save JSON report
        const jsonReportPath = path.join(reportDir, 'report.json');
        fs.writeFileSync(jsonReportPath, JSON.stringify(jsonReport, null, 2));
        console.log(chalk.green(`JSON report saved as ${jsonReportPath}`));

        // Open the HTML report in the default browser if not disabled
        if (!options.noOpen) {
            try {
                const openCommand = process.platform === 'win32' ? 'start' : process.platform === 'darwin' ? 'open' : 'xdg-open';
                execSync(`${openCommand} ${htmlReportPath}`);
                console.log(chalk.yellow('Opening HTML report in your default browser...'));
            } catch (error) {
                console.log(chalk.red(`Failed to open HTML report: ${error.message}`));
                console.log(chalk.yellow(`You can manually open the report at: ${htmlReportPath}`));
            }
        }
    } catch (error) {
        console.error(chalk.red('An error occurred during the scan:'));
        console.error(chalk.red(error.message));
        console.error(chalk.yellow('Stack trace:'));
        console.error(error.stack);
        process.exit(1);
    }
}

function generateJsonReport(scanResult) {
    const report = {};
    if (scanResult.vulnerabilities) {
        scanResult.vulnerabilities.forEach(vuln => {
            if (!report[vuln.file]) {
                report[vuln.file] = [];
            }
            report[vuln.file].push({
                line: vuln.line,
                message: vuln.message,
                type: vuln.type,
                quickFix: vuln.quickFix || 'No quick fix available.'
            });
        });
    }
    return report;
}

// Parse command line arguments
const argv = yargs(hideBin(process.argv))
    .usage('Usage: $0 [options] <path>')
    .option('all', {
        alias: 'a',
        type: 'boolean',
        description: 'Run all scans'
    })
    .option('string', {
        alias: 's',
        type: 'boolean',
        description: 'Run string input sanitization scan'
    })
    .option('cors', {
        alias: 'c',
        type: 'boolean',
        description: 'Run CORS configuration scan'
    })
    .option('auth', {
        alias: 'u',
        type: 'boolean',
        description: 'Run authentication scan'
    })
    .option('authz', {
        alias: 'z',
        type: 'boolean',
        description: 'Run authorization scan'
    })
    .option('no-open', {
        alias: 'n',
        type: 'boolean',
        description: 'Do not automatically open the HTML report'
    })
    .demandCommand(1, 'Please provide the path to the repository you want to scan')
    .help()
    .argv;

// Run the scanner
const repoPath = argv._[0];
scanRepository(repoPath, argv).catch(error => {
    console.error(chalk.red('An unexpected error occurred:'));
    console.error(chalk.red(error.message));
    console.error(chalk.yellow('Stack trace:'));
    console.error(error.stack);
    process.exit(1);
});