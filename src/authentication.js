const fs = require('fs');
const path = require('path');

async function scanAuthentication(repoPath) {
    const files = await getAuthFiles(repoPath);
    const vulnerabilities = [];
    const passedChecks = [];
    let authImplemented = false;
    const checksPerformed = [
        'Authentication implementation detection',
        'JWT token expiration check',
        'Session secret strength check',
        'OAuth state parameter check',
        'Protected routes check'
    ];

    if (files.length === 0) {
        return {
            passed: true,
            authImplemented: false,
            vulnerabilities: [],
            passedChecks: [],
            checksPerformed: [],
            message: 'No relevant files found for authentication scan. This is not necessarily an issue, but ensure it\'s intentional.'
        };
    }

    for (const file of files) {
        const content = await fs.promises.readFile(file, 'utf-8');
        const lines = content.split('\n');
        const relativeFilePath = path.relative(repoPath, file);

        let fileAuthImplemented = false;
        let fileVulnerabilities = [];
        let filePassedChecks = [];

        lines.forEach((line, index) => {
            // Check for authentication implementation
            if (line.includes('authenticate') || line.includes('login') || line.includes('passport')) {
                authImplemented = true;
                fileAuthImplemented = true;

                // Check for JWT usage
                if (line.includes('jwt.sign') || line.includes('jwt.verify')) {
                    // Check for token expiration
                    if (!line.includes('expiresIn') && !line.includes('exp:')) {
                        fileVulnerabilities.push({
                            file: relativeFilePath,
                            line: index + 1,
                            message: 'JWT tokens should have an expiration time.',
                            type: 'Authentication'
                        });
                    } else {
                        filePassedChecks.push({
                            file: relativeFilePath,
                            line: index + 1,
                            message: 'JWT token expiration is properly set.',
                            type: 'Authentication'
                        });
                    }
                }

                // Check for session-based auth
                if (line.includes('express-session')) {
                    if (!line.includes('secret:') || line.match(/secret:\s*['"][^'"]{10,}['"]/)) {
                        fileVulnerabilities.push({
                            file: relativeFilePath,
                            line: index + 1,
                            message: 'Session secret should be a long, random string.',
                            type: 'Authentication'
                        });
                    } else {
                        filePassedChecks.push({
                            file: relativeFilePath,
                            line: index + 1,
                            message: 'Session secret is properly configured.',
                            type: 'Authentication'
                        });
                    }
                }

                // Check for OAuth
                if (line.includes('oauth') || line.includes('OAuth')) {
                    if (!line.includes('state:')) {
                        fileVulnerabilities.push({
                            file: relativeFilePath,
                            line: index + 1,
                            message: 'OAuth implementation should use state parameter to prevent CSRF.',
                            type: 'Authentication'
                        });
                    } else {
                        filePassedChecks.push({
                            file: relativeFilePath,
                            line: index + 1,
                            message: 'OAuth state parameter is properly used.',
                            type: 'Authentication'
                        });
                    }
                }
            }

            // Check for protected routes
            if (line.includes('router.') || line.includes('app.')) {
                if (!line.includes('isAuthenticated') && !line.includes('requireAuth') && !line.includes('verifyToken')) {
                    fileVulnerabilities.push({
                        file: relativeFilePath,
                        line: index + 1,
                        message: 'Route may not be properly protected with authentication middleware.',
                        type: 'Authentication'
                    });
                } else {
                    filePassedChecks.push({
                        file: relativeFilePath,
                        line: index + 1,
                        message: 'Route is properly protected with authentication middleware.',
                        type: 'Authentication'
                    });
                }
            }
        });

        if (fileAuthImplemented) {
            vulnerabilities.push(...fileVulnerabilities);
            passedChecks.push(...filePassedChecks);
        }
    }

    if (!authImplemented) {
        return {
            passed: true,
            authImplemented: false,
            vulnerabilities: [],
            passedChecks: [],
            checksPerformed,
            message: 'No authentication implementation detected. This is not necessarily an issue, but ensure it\'s intentional.'
        };
    }

    return {
        passed: vulnerabilities.length === 0 && passedChecks.length > 0,
        authImplemented,
        vulnerabilities,
        passedChecks,
        checksPerformed
    };
}

async function getAuthFiles(dir) {
    const dirents = await fs.promises.readdir(dir, { withFileTypes: true });
    const files = await Promise.all(dirents.map((dirent) => {
        const res = path.resolve(dir, dirent.name);
        return dirent.isDirectory() ? getAuthFiles(res) : res;
    }));
    return Array.prototype.concat(...files)
        .filter(file => 
            (file.includes('auth') || 
             file.includes('login') || 
             file.includes('user') ||
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

module.exports = scanAuthentication;