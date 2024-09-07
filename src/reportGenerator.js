const cheerio = require('cheerio');
const Table = require('cli-table3');
require('colors');

function generateReport(results, format) {
    if (format === 'terminal') {
        return generateTerminalReport(results);
    } else if (format === 'html') {
        return generateHtmlReport(results);
    }
}

function generateTerminalReport(results) {
    let report = '\n=== PLTECH Security Scan Report ===\n'.bold.green;

    // Summary Table
    const summaryTable = new Table({
        head: ['Check Type', 'Status', 'Issues Found', 'Checks Passed'].map(h => h.bold),
        colWidths: [30, 15, 15, 15]
    });

    let totalIssues = 0;
    let totalPassed = 0;

    for (const [check, result] of Object.entries(results)) {
        const issues = result.vulnerabilities ? result.vulnerabilities.length : 0;
        const passed = result.passedChecks ? result.passedChecks.length : 0;
        const checksPerformed = result.checksPerformed ? result.checksPerformed.length : 0;
        totalIssues += issues;
        totalPassed += passed;

        let status;
        if (checksPerformed === 0) {
            status = 'NO TESTS RUN'.yellow;
        } else if (result.passed) {
            status = 'PASSED'.green;
        } else {
            status = 'FAILED'.red;
        }

        summaryTable.push([
            check,
            status,
            issues.toString(),
            passed.toString()
        ]);
    }

    report += '\nSummary:\n' + summaryTable.toString() + '\n';
    report += `Total Issues Found: ${totalIssues}\n`;
    report += `Total Checks Passed: ${totalPassed}\n\n`;

    // Detailed Results
    for (const [check, result] of Object.entries(results)) {
        report += `${check.toUpperCase()}:\n`.bold.underline;

        if (result.checksPerformed && result.checksPerformed.length > 0) {
            report += `Status: ${result.passed ? 'PASSED'.green : 'FAILED'.red}\n`;
            
            report += 'Checks Performed:\n';
            result.checksPerformed.forEach(check => {
                report += `  - ${check}\n`;
            });

            if (result.vulnerabilities && result.vulnerabilities.length > 0) {
                const vulnTable = new Table({
                    head: ['File', 'Line', 'Column', 'Message'].map(h => h.bold),
                    colWidths: [30, 10, 10, 50]
                });

                result.vulnerabilities.forEach(v => {
                    vulnTable.push([
                        v.file,
                        v.line.toString(),
                        v.column ? v.column.toString() : 'N/A',
                        v.message
                    ]);
                });

                report += 'Vulnerabilities:\n' + vulnTable.toString() + '\n';
            }

            if (result.passedChecks && result.passedChecks.length > 0) {
                const passedTable = new Table({
                    head: ['File', 'Message'].map(h => h.bold),
                    colWidths: [50, 50]
                });

                result.passedChecks.forEach(p => {
                    passedTable.push([
                        p.file,
                        p.message
                    ]);
                });

                report += 'Passed Checks:\n' + passedTable.toString() + '\n';
            }
        } else {
            report += 'Status: '.bold + 'NO TESTS RUN\n'.yellow;
            if (result.message) {
                report += `Message: ${result.message}\n`;
            }
        }

        report += '\n';
    }

    return report;
}

function generateHtmlReport(results) {
    const $ = cheerio.load(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>PLTECH Security Scan Report</title>
            <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
            <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;700&display=swap" rel="stylesheet">
            <style>
                body {
                    font-family: 'Roboto', sans-serif;
                    line-height: 1.6;
                    color: #333;
                    max-width: 1200px;
                    margin: 0 auto;
                    padding: 20px;
                    background-color: #f5f5f5;
                }
                h1, h2, h3 {
                    color: #2c3e50;
                }
                h1 {
                    text-align: center;
                    margin-bottom: 30px;
                }
                .check {
                    background-color: #fff;
                    border-radius: 8px;
                    padding: 20px;
                    margin-bottom: 30px;
                    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
                    transition: all 0.3s ease;
                }
                .check:hover {
                    transform: translateY(-5px);
                    box-shadow: 0 6px 12px rgba(0, 0, 0, 0.15);
                }
                .status {
                    font-weight: bold;
                    padding: 5px 10px;
                    border-radius: 4px;
                    display: inline-block;
                }
                .passed {
                    background-color: #27ae60;
                    color: white;
                }
                .failed {
                    background-color: #c0392b;
                    color: white;
                }
                .no-tests {
                    background-color: #f39c12;
                    color: white;
                }
                .vulnerabilities, .passed-checks {
                    margin-top: 20px;
                }
                table {
                    width: 100%;
                    border-collapse: collapse;
                    margin-bottom: 20px;
                }
                th, td {
                    border: 1px solid #ddd;
                    padding: 12px;
                    text-align: left;
                }
                th {
                    background-color: #f2f2f2;
                    font-weight: bold;
                }
                tr:nth-child(even) {
                    background-color: #f9f9f9;
                }
                #chart {
                    width: 100%;
                    max-width: 600px;
                    margin: 30px auto;
                }
                #summary {
                    text-align: center;
                    font-size: 1.2em;
                    margin-bottom: 30px;
                }
                @media (max-width: 768px) {
                    body {
                        padding: 10px;
                    }
                    table {
                        font-size: 14px;
                    }
                }
            </style>
        </head>
        <body>
            <h1>PLTECH Security Scan Report</h1>
            <div id="summary"></div>
            <div id="chart">
                <canvas id="securityChart"></canvas>
            </div>
            <div id="results"></div>
            <script>
                const ctx = document.getElementById('securityChart').getContext('2d');
                const data = ${JSON.stringify(results)};
                const labels = Object.keys(data);
                const values = labels.map(label => ({
                    passed: data[label].passedChecks ? data[label].passedChecks.length : 0,
                    failed: data[label].vulnerabilities ? data[label].vulnerabilities.length : 0,
                    noTests: (data[label].checksPerformed && data[label].checksPerformed.length === 0) ? 1 : 0
                }));
                new Chart(ctx, {
                    type: 'bar',
                    data: {
                        labels: labels,
                        datasets: [
                            {
                                label: 'Passed Checks',
                                data: values.map(v => v.passed),
                                backgroundColor: '#27ae60',
                            },
                            {
                                label: 'Failed Checks',
                                data: values.map(v => v.failed),
                                backgroundColor: '#c0392b',
                            },
                            {
                                label: 'No Tests Run',
                                data: values.map(v => v.noTests),
                                backgroundColor: '#f39c12',
                            }
                        ]
                    },
                    options: {
                        responsive: true,
                        scales: {
                            x: {
                                stacked: true,
                            },
                            y: {
                                stacked: true
                            }
                        },
                        plugins: {
                            legend: {
                                position: 'top',
                            },
                            title: {
                                display: true,
                                text: 'Security Scan Results'
                            }
                        }
                    }
                });
            </script>
        </body>
        </html>
    `);

    const $results = $('#results');
    let totalIssues = 0;
    let totalPassed = 0;
    let totalNoTests = 0;

    // Summary Table
    const $summaryTable = $('<table>').append('<tr><th>Check Type</th><th>Status</th><th>Issues Found</th><th>Checks Passed</th></tr>');

    for (const [check, result] of Object.entries(results)) {
        const issues = result.vulnerabilities ? result.vulnerabilities.length : 0;
        const passed = result.passedChecks ? result.passedChecks.length : 0;
        const checksPerformed = result.checksPerformed ? result.checksPerformed.length : 0;
        totalIssues += issues;
        totalPassed += passed;

        let status, statusClass;
        if (checksPerformed === 0) {
            status = 'NO TESTS RUN';
            statusClass = 'no-tests';
            totalNoTests++;
        } else if (result.passed) {
            status = 'PASSED';
            statusClass = 'passed';
        } else {
            status = 'FAILED';
            statusClass = 'failed';
        }

        $summaryTable.append(`
            <tr>
                <td>${check}</td>
                <td><span class="status ${statusClass}">${status}</span></td>
                <td>${issues}</td>
                <td>${passed}</td>
            </tr>
        `);
    }

    $('#summary').append('<h2>Summary</h2>').append($summaryTable).append(`
        <p>Total Issues Found: ${totalIssues}</p>
        <p>Total Checks Passed: ${totalPassed}</p>
        <p>Total Checks with No Tests Run: ${totalNoTests}</p>
    `);

    // Detailed Results
    for (const [check, result] of Object.entries(results)) {
        const $check = $('<div class="check">');
        $check.append(`<h2>${check}</h2>`);

        if (result.checksPerformed && result.checksPerformed.length > 0) {
            $check.append(`<p>Status: <span class="status ${result.passed ? 'passed' : 'failed'}">${result.passed ? 'PASSED' : 'FAILED'}</span></p>`);
            
            $check.append('<h3>Checks Performed:</h3>');
            const $checksList = $('<ul>');
            result.checksPerformed.forEach(checkItem => {
                $checksList.append(`<li>${checkItem}</li>`);
            });
            $check.append($checksList);

            if (result.vulnerabilities && result.vulnerabilities.length > 0) {
                $check.append('<h3>Vulnerabilities:</h3>');
                const $vulnTable = $('<table>').append('<tr><th>File</th><th>Line</th><th>Column</th><th>Message</th></tr>');
                result.vulnerabilities.forEach(v => {
                    $vulnTable.append(`
                        <tr>
                            <td>${v.file}</td>
                            <td>${v.line}</td>
                            <td>${v.column || 'N/A'}</td>
                            <td>${v.message}</td>
                        </tr>
                    `);
                });
                $check.append($vulnTable);
            }

            if (result.passedChecks && result.passedChecks.length > 0) {
                $check.append('<h3>Passed Checks:</h3>');
                const $passedTable = $('<table>').append('<tr><th>File</th><th>Message</th></tr>');
                result.passedChecks.forEach(p => {
                    $passedTable.append(`
                        <tr>
                            <td>${p.file}</td>
                            <td>${p.message}</td>
                        </tr>
                    `);
                });
                $check.append($passedTable);
            }
        } else {
            $check.append('<p>Status: <span class="status no-tests">NO TESTS RUN</span></p>');
            if (result.message) {
                $check.append(`<p>Message: ${result.message}</p>`);
            }
        }

        $results.append($check);
    }

    return $.html();
}

module.exports = generateReport;