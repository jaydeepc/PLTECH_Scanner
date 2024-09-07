const fs = require('fs');
const path = require('path');

function scanAuthentication(repoPath) {
    const files = getAuthFiles(repoPath);
    let authImplemented = false;
    let authFile = '';

    for (const file of files) {
        const content = fs.readFileSync(file, 'utf8');
        if (content.includes('authenticate') || content.includes('login') || content.includes('passport')) {
            authImplemented = true;
            authFile = path.relative(repoPath, file);
            break;
        }
    }

    return {
        passed: authImplemented,
        message: authImplemented 
            ? `Authentication is implemented in ${authFile}`
            : 'Authentication implementation not found'
    };
}

function getAuthFiles(dir) {
    const dirents = fs.readdirSync(dir, { withFileTypes: true });
    const files = dirents.map((dirent) => {
        const res = path.resolve(dir, dirent.name);
        return dirent.isDirectory() ? getAuthFiles(res) : res;
    });
    return Array.prototype.concat(...files)
        .filter(file => file.includes('auth') || file.includes('login') || file.includes('user'))
        .filter(file => !file.includes('node_modules') &&
                        !file.includes('lib') &&
                        !file.includes('vendor') &&
                        !file.includes('dist') &&
                        !file.includes('build') &&
                        !file.includes('.venv') &&
                        !file.includes('venv') &&
                        !file.includes('env') &&
                        !file.includes('__pycache__') &&
                        !file.includes('.git'));
}

module.exports = scanAuthentication;