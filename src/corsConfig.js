const fs = require('fs');
const path = require('path');

function scanCorsConfiguration(repoPath) {
    const files = getConfigFiles(repoPath);
    let corsConfigured = false;
    let configFile = '';

    for (const file of files) {
        const content = fs.readFileSync(file, 'utf8');
        if (content.includes('cors')) {
            corsConfigured = true;
            configFile = path.relative(repoPath, file);
            break;
        }
    }

    return {
        passed: corsConfigured,
        message: corsConfigured 
            ? `CORS is configured in ${configFile}`
            : 'CORS configuration not found'
    };
}

function getConfigFiles(dir) {
    const dirents = fs.readdirSync(dir, { withFileTypes: true });
    const files = dirents.map((dirent) => {
        const res = path.resolve(dir, dirent.name);
        return dirent.isDirectory() ? getConfigFiles(res) : res;
    });
    return Array.prototype.concat(...files)
        .filter(file => file.includes('config') || file.includes('server'))
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

module.exports = scanCorsConfiguration;