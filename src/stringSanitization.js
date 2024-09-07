const { ESLint } = require('eslint');
const path = require('path');
const fs = require('fs');

async function scanStringInputSanitization(repoPath) {
    const eslint = new ESLint({
        useEslintrc: false,
        overrideConfig: {
            env: {
                node: true,
                es2021: true
            },
            parserOptions: {
                ecmaVersion: 2021
            },
            plugins: ['security'],
            extends: ['plugin:security/recommended'],
            rules: {
                'no-eval': 'error',
                'security/detect-object-injection': 'error',
                'security/detect-non-literal-regexp': 'error',
                'security/detect-unsafe-regex': 'error'
            }
        },
        resolvePluginsRelativeTo: __dirname
    });

    const files = await getJavaScriptFiles(repoPath);
    const results = await eslint.lintFiles(files);
    
    const vulnerabilities = results.flatMap(result => 
        result.messages.filter(msg => 
            msg.ruleId && (
                msg.ruleId.includes('no-eval') ||
                msg.ruleId.includes('security/detect-object-injection') ||
                msg.ruleId.includes('security/detect-non-literal-regexp') ||
                msg.ruleId.includes('security/detect-unsafe-regex')
            )
        )
    );

    return {
        passed: vulnerabilities.length === 0,
        vulnerabilities: vulnerabilities.map(v => ({
            file: v.filePath,
            line: v.line,
            column: v.column,
            message: v.message
        }))
    };
}

async function getJavaScriptFiles(dir) {
    const dirents = await fs.promises.readdir(dir, { withFileTypes: true });
    const files = await Promise.all(dirents.map((dirent) => {
        const res = path.resolve(dir, dirent.name);
        if (dirent.isDirectory()) {
            if (!shouldIgnoreDirectory(dirent.name)) {
                return getJavaScriptFiles(res);
            }
            return [];
        } else {
            return res;
        }
    }));
    return Array.prototype.concat(...files)
        .filter(file => file.endsWith('.js'));
}

function shouldIgnoreDirectory(dirName) {
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
    return ignoreDirs.includes(dirName);
}

module.exports = scanStringInputSanitization;