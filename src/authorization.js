const fs = require('fs');
const path = require('path');

async function scanAuthorization(repoPath) {
    const files = await getAuthFiles(repoPath);
    const vulnerabilities = [];
    const passedChecks = [];
    let authorizationImplemented = false;
    const checksPerformed = [
        'Authorization implementation detection',
        'RBAC implementation check',
        'Hardcoded role checks',
        'Sensitive route protection',
        'Separation of authentication and authorization'
    ];

    if (files.length === 0) {
        return {
            noRelevantFiles: true,
            message: 'No relevant files found for authorization scan.'
        };
    }

    for (const file of files) {
        const content = await fs.promises.readFile(file, 'utf-8');
        const lines = content.split('\n');
        const relativeFilePath = path.relative(repoPath, file);

        let fileAuthorizationImplemented = false;
        let fileVulnerabilities = [];
        let filePassedChecks = [];

        lines.forEach((line, index) => {
            // Check for authorization implementation
            if (line.includes('authorize') || line.includes('permission') || line.includes('role')) {
                authorizationImplemented = true;
                fileAuthorizationImplemented = true;

                // Check for RBAC
                if (line.includes('role') || line.includes('permission')) {
                    if (!line.match(/check(Role|Permission)/i)) {
                        fileVulnerabilities.push({
                            file: relativeFilePath,
                            line: index + 1,
                            message: 'Role/Permission checks may not be properly implemented.',
                            type: 'Authorization',
                            quickFix: 'Implement proper role/permission checking functions.'
                        });
                    } else {
                        filePassedChecks.push({
                            file: relativeFilePath,
                            line: index + 1,
                            message: 'Role/Permission checks are properly implemented.',
                            type: 'Authorization'
                        });
                    }
                }

                // Check for hardcoded roles or permissions
                const hardcodedRoles = line.match(/role\s*===?\s*['"][\w-]+['"]/);
                if (hardcodedRoles) {
                    fileVulnerabilities.push({
                        file: relativeFilePath,
                        line: index + 1,
                        message: 'Hardcoded role checks found. Consider using a more flexible RBAC system.',
                        type: 'Authorization',
                        quickFix: 'Use a dynamic role checking system instead of hardcoding roles.'
                    });
                }
            }

            // Check for sensitive routes
            if (line.includes('router.') || line.includes('app.')) {
                if (line.includes('admin') || line.includes('settings') || line.includes('config')) {
                    if (!line.includes('isAuthorized') && !line.includes('checkPermission') && !line.includes('hasRole')) {
                        fileVulnerabilities.push({
                            file: relativeFilePath,
                            line: index + 1,
                            message: 'Sensitive route may not be properly protected with authorization checks.',
                            type: 'Authorization',
                            quickFix: 'Add authorization middleware to protect sensitive routes.'
                        });
                    } else {
                        filePassedChecks.push({
                            file: relativeFilePath,
                            line: index + 1,
                            message: 'Sensitive route is properly protected with authorization checks.',
                            type: 'Authorization'
                        });
                    }
                }
            }
        });

        // Check for proper separation of authentication and authorization
        if (content.includes('authenticate') && content.includes('authorize')) {
            const authLine = lines.findIndex(line => line.includes('authenticate'));
            const authzLine = lines.findIndex(line => line.includes('authorize'));
            if (Math.abs(authLine - authzLine) <= 1) {
                fileVulnerabilities.push({
                    file: relativeFilePath,
                    line: Math.min(authLine, authzLine) + 1,
                    message: 'Authentication and authorization should be separate concerns.',
                    type: 'Authorization',
                    quickFix: 'Separate authentication and authorization logic into different modules or middleware.'
                });
            } else {
                filePassedChecks.push({
                    file: relativeFilePath,
                    message: 'Authentication and authorization are properly separated.',
                    type: 'Authorization'
                });
            }
        }

        if (fileAuthorizationImplemented) {
            vulnerabilities.push(...fileVulnerabilities);
            passedChecks.push(...filePassedChecks);
        }
    }

    if (!authorizationImplemented) {
        return {
            noRelevantFiles: true,
            message: 'No authorization implementation detected. This is not necessarily an issue, but ensure it\'s intentional.'
        };
    }

    return {
        passed: vulnerabilities.length === 0 && passedChecks.length > 0,
        authorizationImplemented,
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
             file.includes('middleware') || 
             file.includes('permission') ||
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

module.exports = scanAuthorization;