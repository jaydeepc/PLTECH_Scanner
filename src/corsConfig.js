const fs = require('fs');
const path = require('path');

async function scanCorsConfiguration(repoPath) {
    const files = await getConfigFiles(repoPath);
    const vulnerabilities = [];
    const passedChecks = [];
    let corsConfigured = false;
    const checksPerformed = ['CORS configuration detection'];

    if (files.length === 0) {
        return {
            noRelevantFiles: true,
            message: 'No relevant files found for CORS configuration scan.'
        };
    }

    for (const file of files) {
        const content = await fs.promises.readFile(file, 'utf-8');
        const lines = content.split('\n');
        const relativeFilePath = path.relative(repoPath, file);

        let fileChecked = false;

        lines.forEach((line, index) => {
            if (line.includes('cors')) {
                corsConfigured = true;
                fileChecked = true;

                // Check for wildcard origin
                if (line.includes("'*'") || line.includes('"*"')) {
                    vulnerabilities.push({
                        file: relativeFilePath,
                        line: index + 1,
                        message: 'CORS allows all origins (*). This is potentially insecure.',
                        type: 'CORS',
                        quickFix: 'Specify allowed origins explicitly instead of using "*".'
                    });
                } else {
                    passedChecks.push({
                        file: relativeFilePath,
                        line: index + 1,
                        message: 'CORS origin is properly configured.',
                        type: 'CORS'
                    });
                }

                // Check for insecure methods
                if (line.includes('methods:') && line.includes('*')) {
                    vulnerabilities.push({
                        file: relativeFilePath,
                        line: index + 1,
                        message: 'CORS allows all methods (*). This is potentially insecure.',
                        type: 'CORS',
                        quickFix: 'Specify allowed methods explicitly instead of using "*".'
                    });
                } else if (line.includes('methods:')) {
                    passedChecks.push({
                        file: relativeFilePath,
                        line: index + 1,
                        message: 'CORS methods are properly configured.',
                        type: 'CORS'
                    });
                }

                // Check for insecure headers
                if (line.includes('allowedHeaders:') && line.includes('*')) {
                    vulnerabilities.push({
                        file: relativeFilePath,
                        line: index + 1,
                        message: 'CORS allows all headers (*). This is potentially insecure.',
                        type: 'CORS',
                        quickFix: 'Specify allowed headers explicitly instead of using "*".'
                    });
                } else if (line.includes('allowedHeaders:')) {
                    passedChecks.push({
                        file: relativeFilePath,
                        line: index + 1,
                        message: 'CORS headers are properly configured.',
                        type: 'CORS'
                    });
                }

                // Check for credentials
                if (line.includes('credentials: true')) {
                    vulnerabilities.push({
                        file: relativeFilePath,
                        line: index + 1,
                        message: 'CORS allows credentials. Ensure this is necessary and origins are strictly limited.',
                        type: 'CORS',
                        quickFix: 'Only set credentials to true if absolutely necessary. If used, ensure origins are strictly limited.'
                    });
                } else if (line.includes('credentials:')) {
                    passedChecks.push({
                        file: relativeFilePath,
                        line: index + 1,
                        message: 'CORS credentials are properly configured.',
                        type: 'CORS'
                    });
                }
            }
        });

        if (fileChecked) {
            passedChecks.push({
                file: relativeFilePath,
                message: 'File checked for CORS configuration.',
                type: 'CORS'
            });
        }
    }

    if (!corsConfigured) {
        return {
            noRelevantFiles: true,
            message: 'CORS is not configured in this project. This is not necessarily an issue, but ensure it\'s intentional.'
        };
    }

    return {
        passed: vulnerabilities.length === 0 && passedChecks.length > 0,
        corsConfigured,
        vulnerabilities,
        passedChecks,
        checksPerformed
    };
}

async function getConfigFiles(dir) {
    const dirents = await fs.promises.readdir(dir, { withFileTypes: true });
    const files = await Promise.all(dirents.map((dirent) => {
        const res = path.resolve(dir, dirent.name);
        return dirent.isDirectory() ? getConfigFiles(res) : res;
    }));
    return Array.prototype.concat(...files)
        .filter(file => 
            (file.includes('config') || 
             file.includes('server') || 
             file.endsWith('.js') || 
             file.endsWith('.ts') || 
             file.endsWith('.py') || 
             file.endsWith('.php') || 
             file.endsWith('.java')) &&
            !shouldIgnoreFile(file)
        );
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

module.exports = scanCorsConfiguration;