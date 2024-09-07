const { ESLint } = require('eslint');
const path = require('path');
const fs = require('fs');

async function scanStringInputSanitization(repoPath) {
    const vulnerabilities = [];
    const passedChecks = [];
    const checksPerformed = [];

    // Determine the languages used in the repository
    const languages = await determineLanguages(repoPath);

    if (languages.size === 0) {
        return {
            passed: false,
            vulnerabilities: [],
            passedChecks: [],
            checksPerformed: [],
            message: 'No supported language files found for string input sanitization scan.'
        };
    }

    if (languages.has('javascript')) {
        checksPerformed.push('JavaScript (ESLint with security plugin)');
        const jsResults = await scanJavaScript(repoPath);
        vulnerabilities.push(...jsResults.vulnerabilities);
        passedChecks.push(...jsResults.passedChecks);
    }

    if (languages.has('python')) {
        checksPerformed.push('Python (custom regex patterns)');
        const pythonResults = await scanPython(repoPath);
        vulnerabilities.push(...pythonResults.vulnerabilities);
        passedChecks.push(...pythonResults.passedChecks);
    }

    if (languages.has('php')) {
        checksPerformed.push('PHP (custom regex patterns)');
        const phpResults = await scanPHP(repoPath);
        vulnerabilities.push(...phpResults.vulnerabilities);
        passedChecks.push(...phpResults.passedChecks);
    }

    if (languages.has('java')) {
        checksPerformed.push('Java (custom regex patterns)');
        const javaResults = await scanJava(repoPath);
        vulnerabilities.push(...javaResults.vulnerabilities);
        passedChecks.push(...javaResults.passedChecks);
    }

    return {
        passed: vulnerabilities.length === 0 && passedChecks.length > 0,
        vulnerabilities: vulnerabilities,
        passedChecks: passedChecks,
        checksPerformed: checksPerformed
    };
}

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
                languages.add('javascript');
                break;
            case '.py':
                languages.add('python');
                break;
            case '.php':
                languages.add('php');
                break;
            case '.java':
                languages.add('java');
                break;
        }
    });

    return languages;
}

async function scanJavaScript(repoPath) {
    const eslint = new ESLint({
        useEslintrc: false,
        overrideConfig: {
            env: {
                node: true,
                browser: true,
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
                'security/detect-unsafe-regex': 'error',
                'security/detect-buffer-noassert': 'error',
                'security/detect-child-process': 'error',
                'security/detect-disable-mustache-escape': 'error',
                'security/detect-eval-with-expression': 'error',
                'security/detect-no-csrf-before-method-override': 'error',
                'security/detect-non-literal-fs-filename': 'error',
                'security/detect-pseudoRandomBytes': 'error',
                'security/detect-possible-timing-attacks': 'error'
            }
        },
        resolvePluginsRelativeTo: __dirname
    });

    const files = await getFiles(repoPath, ['.js', '.jsx', '.ts', '.tsx']);
    const results = await eslint.lintFiles(files);
    
    const vulnerabilities = [];
    const passedChecks = [];

    results.forEach(result => {
        if (result.messages.length > 0) {
            vulnerabilities.push(...result.messages.map(msg => ({
                file: result.filePath,
                line: msg.line,
                column: msg.column,
                message: `${msg.ruleId}: ${msg.message}`,
                type: 'JavaScript'
            })));
        } else {
            passedChecks.push({
                file: result.filePath,
                message: 'Passed all ESLint security checks',
                type: 'JavaScript'
            });
        }
    });

    return { vulnerabilities, passedChecks };
}

async function scanPython(repoPath) {
    const vulnerabilities = [];
    const passedChecks = [];
    const pythonFiles = await getFiles(repoPath, ['.py']);

    for (const file of pythonFiles) {
        const content = await fs.promises.readFile(file, 'utf-8');
        const lines = content.split('\n');
        let fileVulnerabilities = [];
        
        lines.forEach((line, index) => {
            // Check for SQL injection vulnerabilities
            if (line.includes('execute(') && !line.includes('parameterized')) {
                fileVulnerabilities.push({
                    file,
                    line: index + 1,
                    message: 'Potential SQL injection vulnerability. Use parameterized queries.',
                    type: 'Python'
                });
            }

            // Check for XSS vulnerabilities
            if (line.includes('render(') && !line.includes('escape')) {
                fileVulnerabilities.push({
                    file,
                    line: index + 1,
                    message: 'Potential XSS vulnerability. Use escape functions for user input.',
                    type: 'Python'
                });
            }

            // Check for unsafe input handling
            if (line.includes('input(') && !line.includes('validate')) {
                fileVulnerabilities.push({
                    file,
                    line: index + 1,
                    message: 'Unsafe input handling. Validate and sanitize user input.',
                    type: 'Python'
                });
            }
        });

        if (fileVulnerabilities.length > 0) {
            vulnerabilities.push(...fileVulnerabilities);
        } else {
            passedChecks.push({
                file,
                message: 'Passed all Python security checks',
                type: 'Python'
            });
        }
    }

    return { vulnerabilities, passedChecks };
}

async function scanPHP(repoPath) {
    const vulnerabilities = [];
    const passedChecks = [];
    const phpFiles = await getFiles(repoPath, ['.php']);

    for (const file of phpFiles) {
        const content = await fs.promises.readFile(file, 'utf-8');
        const lines = content.split('\n');
        let fileVulnerabilities = [];
        
        lines.forEach((line, index) => {
            // Check for SQL injection vulnerabilities
            if ((line.includes('mysql_query(') || line.includes('$_GET') || line.includes('$_POST')) && !line.includes('prepared')) {
                fileVulnerabilities.push({
                    file,
                    line: index + 1,
                    message: 'Potential SQL injection vulnerability. Use prepared statements.',
                    type: 'PHP'
                });
            }

            // Check for XSS vulnerabilities
            if (line.includes('echo') && !line.includes('htmlspecialchars')) {
                fileVulnerabilities.push({
                    file,
                    line: index + 1,
                    message: 'Potential XSS vulnerability. Use htmlspecialchars() for output escaping.',
                    type: 'PHP'
                });
            }

            // Check for unsafe file inclusion
            if ((line.includes('include(') || line.includes('require(')) && !line.includes('validate')) {
                fileVulnerabilities.push({
                    file,
                    line: index + 1,
                    message: 'Unsafe file inclusion. Validate file paths before inclusion.',
                    type: 'PHP'
                });
            }
        });

        if (fileVulnerabilities.length > 0) {
            vulnerabilities.push(...fileVulnerabilities);
        } else {
            passedChecks.push({
                file,
                message: 'Passed all PHP security checks',
                type: 'PHP'
            });
        }
    }

    return { vulnerabilities, passedChecks };
}

async function scanJava(repoPath) {
    const vulnerabilities = [];
    const passedChecks = [];
    const javaFiles = await getFiles(repoPath, ['.java']);

    for (const file of javaFiles) {
        const content = await fs.promises.readFile(file, 'utf-8');
        const lines = content.split('\n');
        let fileVulnerabilities = [];
        
        lines.forEach((line, index) => {
            // Check for SQL injection vulnerabilities
            if (line.includes('executeQuery(') && !line.includes('PreparedStatement')) {
                fileVulnerabilities.push({
                    file,
                    line: index + 1,
                    message: 'Potential SQL injection vulnerability. Use PreparedStatement.',
                    type: 'Java'
                });
            }

            // Check for XSS vulnerabilities
            if (line.includes('getParameter(') && !line.includes('escapeHtml')) {
                fileVulnerabilities.push({
                    file,
                    line: index + 1,
                    message: 'Potential XSS vulnerability. Use escapeHtml() for user input.',
                    type: 'Java'
                });
            }

            // Check for unsafe deserialization
            if (line.includes('ObjectInputStream(') && !line.includes('validateObject')) {
                fileVulnerabilities.push({
                    file,
                    line: index + 1,
                    message: 'Unsafe deserialization. Validate and sanitize input before deserialization.',
                    type: 'Java'
                });
            }
        });

        if (fileVulnerabilities.length > 0) {
            vulnerabilities.push(...fileVulnerabilities);
        } else {
            passedChecks.push({
                file,
                message: 'Passed all Java security checks',
                type: 'Java'
            });
        }
    }

    return { vulnerabilities, passedChecks };
}

async function getFiles(dir, extensions = null) {
    const dirents = await fs.promises.readdir(dir, { withFileTypes: true });
    const files = await Promise.all(dirents.map((dirent) => {
        const res = path.resolve(dir, dirent.name);
        return dirent.isDirectory()
            ? getFiles(res, extensions)
            : res;
    }));
    let flattenedFiles = Array.prototype.concat(...files);
    
    if (extensions) {
        flattenedFiles = flattenedFiles.filter(file => extensions.includes(path.extname(file).toLowerCase()));
    }
    
    return flattenedFiles.filter(file => !shouldIgnoreFile(file));
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

module.exports = scanStringInputSanitization;