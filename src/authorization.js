const fs = require('fs');
const path = require('path');

function scanAuthorization(repoPath) {
    const files = getAuthFiles(repoPath);
    let authorizationImplemented = false;
    let authFile = '';

    for (const file of files) {
        const content = fs.readFileSync(file, 'utf8');
        if (content.includes('authorize') || content.includes('permission') || content.includes('role')) {
            authorizationImplemented = true;
            authFile = path.relative(repoPath, file);
            break;
        }
    }

    return {
        passed: authorizationImplemented,
        message: authorizationImplemented 
            ? `Authorization is implemented in ${authFile}`
            : 'Authorization implementation not found'
    };
}

function getAuthFiles(dir) {
    const dirents = fs.readdirSync(dir, { withFileTypes: true });
    const files = dirents.map((dirent) => {
        const res = path.resolve(dir, dirent.name);
        return dirent.isDirectory() ? getAuthFiles(res) : res;
    });
    return Array.prototype.concat(...files)
        .filter(file => file.includes('auth') || file.includes('middleware') || file.includes('permission'))
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

module.exports = scanAuthorization;