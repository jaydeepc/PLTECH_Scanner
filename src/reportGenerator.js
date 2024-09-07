const cheerio = require('cheerio');

function generateReport(results, format) {
    if (format === 'terminal') {
        return generateTerminalReport(results);
    } else if (format === 'html') {
        return generateHtmlReport(results);
    }
}

function generateTerminalReport(results) {
    let report = '\n=== Security Scan Report ===\n\n';

    for (const [check, result] of Object.entries(results)) {
        report += `${check}:\n`;
        report += `  Status: ${result.passed ? 'PASSED' : 'FAILED'}\n`;
        
        if (result.message) {
            report += `  Message: ${result.message}\n`;
        }

        if (result.vulnerabilities && result.vulnerabilities.length > 0) {
            report += '  Vulnerabilities:\n';
            result.vulnerabilities.forEach(v => {
                report += `    - ${v.file} (Line ${v.line}, Column ${v.column}): ${v.message}\n`;
            });
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
            <title>Security Scan Report</title>
            <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
            <style>
                body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 800px; margin: 0 auto; padding: 20px; }
                h1 { color: #2c3e50; text-align: center; }
                .check { background-color: #f9f9f9; border-radius: 5px; padding: 15px; margin-bottom: 20px; transition: all 0.3s ease; }
                .check:hover { transform: translateY(-5px); box-shadow: 0 5px 15px rgba(0,0,0,0.1); }
                .check h2 { margin-top: 0; color: #34495e; }
                .status { font-weight: bold; }
                .passed { color: #27ae60; }
                .failed { color: #c0392b; }
                .vulnerabilities { margin-top: 10px; }
                .vulnerability { background-color: #ecf0f1; padding: 10px; border-radius: 3px; margin-bottom: 5px; }
                #chart { width: 100%; max-width: 600px; margin: 20px auto; }
            </style>
        </head>
        <body>
            <h1>Security Scan Report</h1>
            <div id="chart">
                <canvas id="securityChart"></canvas>
            </div>
            <div id="results"></div>
            <script>
                const ctx = document.getElementById('securityChart').getContext('2d');
                const data = ${JSON.stringify(results)};
                const labels = Object.keys(data);
                const values = labels.map(label => data[label].passed ? 1 : 0);
                new Chart(ctx, {
                    type: 'pie',
                    data: {
                        labels: labels,
                        datasets: [{
                            data: values,
                            backgroundColor: values.map(v => v === 1 ? '#27ae60' : '#c0392b'),
                        }]
                    },
                    options: {
                        responsive: true,
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

    for (const [check, result] of Object.entries(results)) {
        const $check = $('<div class="check">');
        $check.append(`<h2>${check}</h2>`);
        $check.append(`<p class="status ${result.passed ? 'passed' : 'failed'}">Status: ${result.passed ? 'PASSED' : 'FAILED'}</p>`);
        
        if (result.message) {
            $check.append(`<p>Message: ${result.message}</p>`);
        }

        if (result.vulnerabilities && result.vulnerabilities.length > 0) {
            const $vulns = $('<div class="vulnerabilities">');
            $vulns.append('<h3>Vulnerabilities:</h3>');
            result.vulnerabilities.forEach(v => {
                $vulns.append(`<div class="vulnerability">${v.file} (Line ${v.line}, Column ${v.column}): ${v.message}</div>`);
            });
            $check.append($vulns);
        }

        $results.append($check);
    }

    return $.html();
}

module.exports = generateReport;