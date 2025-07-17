class SecurityScanner {
    constructor() {
        this.isScanning = false;
        this.results = {
            vulnerabilities: [],
            endpoints: [],
            headers: {},
            logs: []
        };
        this.initializeEventListeners();
    }

    initializeEventListeners() {
        document.getElementById('start-scan').addEventListener('click', () => this.startScan());
        
        // Tab switching
        document.querySelectorAll('.tab-button').forEach(button => {
            button.addEventListener('click', (e) => this.switchTab(e.target.dataset.tab));
        });
    }

    async startScan() {
        const targetUrl = document.getElementById('target-url').value.trim();
        
        if (!targetUrl) {
            alert('Please enter a target URL');
            return;
        }

        if (!this.isValidUrl(targetUrl)) {
            alert('Please enter a valid URL (including http:// or https://)');
            return;
        }

        this.isScanning = true;
        this.updateScanButton(true);
        this.showProgress();
        this.clearResults();
        
        try {
            await this.performScan(targetUrl);
        } catch (error) {
            this.addLog('ERROR', `Scan failed: ${error.message}`);
        } finally {
            this.isScanning = false;
            this.updateScanButton(false);
            this.hideProgress();
        }
    }

    async performScan(targetUrl) {
        const scanOptions = this.getScanOptions();
        let progress = 0;
        const totalSteps = Object.keys(scanOptions).filter(key => scanOptions[key]).length;

        this.addLog('INFO', `Starting security scan for: ${targetUrl}`);
        this.updateProgress(0, 'Initializing scan...');

        // Security Headers Check
        if (scanOptions.securityHeaders) {
            this.updateProgress(++progress / totalSteps * 100, 'Checking security headers...');
            await this.checkSecurityHeaders(targetUrl);
            await this.delay(500);
        }

        // SSL/TLS Analysis
        if (scanOptions.sslTls) {
            this.updateProgress(++progress / totalSteps * 100, 'Analyzing SSL/TLS configuration...');
            await this.checkSSLTLS(targetUrl);
            await this.delay(500);
        }

        // Endpoint Discovery
        if (scanOptions.endpointDiscovery) {
            this.updateProgress(++progress / totalSteps * 100, 'Discovering endpoints...');
            await this.discoverEndpoints(targetUrl);
            await this.delay(500);
        }

        // SQL Injection Testing
        if (scanOptions.sqlInjection) {
            this.updateProgress(++progress / totalSteps * 100, 'Testing for SQL injection...');
            await this.testSQLInjection(targetUrl);
            await this.delay(500);
        }

        // XSS Testing
        if (scanOptions.xss) {
            this.updateProgress(++progress / totalSteps * 100, 'Testing for XSS vulnerabilities...');
            await this.testXSS(targetUrl);
            await this.delay(500);
        }

        // Directory Traversal
        if (scanOptions.directoryTraversal) {
            this.updateProgress(++progress / totalSteps * 100, 'Testing directory traversal...');
            await this.testDirectoryTraversal(targetUrl);
            await this.delay(500);
        }

        // CSRF Detection
        if (scanOptions.csrf) {
            this.updateProgress(++progress / totalSteps * 100, 'Checking CSRF protection...');
            await this.checkCSRF(targetUrl);
            await this.delay(500);
        }

        // Authentication Bypass
        if (scanOptions.authBypass) {
            this.updateProgress(++progress / totalSteps * 100, 'Testing authentication bypass...');
            await this.testAuthBypass(targetUrl);
            await this.delay(500);
        }

        this.updateProgress(100, 'Scan completed!');
        this.updateOverview();
        this.addLog('SUCCESS', 'Security scan completed successfully');
    }

    async checkSecurityHeaders(url) {
        try {
            // Simulate security header check
            const headers = {
                'X-Frame-Options': Math.random() > 0.5 ? 'DENY' : null,
                'X-XSS-Protection': Math.random() > 0.3 ? '1; mode=block' : null,
                'X-Content-Type-Options': Math.random() > 0.4 ? 'nosniff' : null,
                'Strict-Transport-Security': Math.random() > 0.6 ? 'max-age=31536000' : null,
                'Content-Security-Policy': Math.random() > 0.7 ? "default-src 'self'" : null,
                'Referrer-Policy': Math.random() > 0.5 ? 'strict-origin-when-cross-origin' : null
            };

            this.results.headers = headers;

            // Check for missing security headers
            Object.entries(headers).forEach(([header, value]) => {
                if (!value) {
                    this.results.vulnerabilities.push({
                        type: 'Missing Security Header',
                        severity: 'medium',
                        title: `Missing ${header} header`,
                        description: `The ${header} security header is not present, which may expose the application to certain attacks.`,
                        details: `Header: ${header}\nStatus: Missing\nRecommendation: Implement proper ${header} header`
                    });
                }
            });

            this.addLog('INFO', 'Security headers analysis completed');
        } catch (error) {
            this.addLog('ERROR', `Security headers check failed: ${error.message}`);
        }
    }

    async checkSSLTLS(url) {
        try {
            const isHttps = url.startsWith('https://');
            
            if (!isHttps) {
                this.results.vulnerabilities.push({
                    type: 'SSL/TLS',
                    severity: 'high',
                    title: 'Unencrypted Connection',
                    description: 'The website is not using HTTPS, which means data transmission is not encrypted.',
                    details: 'Protocol: HTTP\nEncryption: None\nRecommendation: Implement HTTPS with valid SSL certificate'
                });
            } else {
                // Simulate SSL/TLS checks
                const sslIssues = [];
                
                if (Math.random() > 0.8) {
                    sslIssues.push('Weak cipher suites detected');
                }
                
                if (Math.random() > 0.9) {
                    sslIssues.push('Certificate chain issues');
                }

                sslIssues.forEach(issue => {
                    this.results.vulnerabilities.push({
                        type: 'SSL/TLS',
                        severity: 'medium',
                        title: issue,
                        description: `SSL/TLS configuration issue detected: ${issue}`,
                        details: `Issue: ${issue}\nRecommendation: Update SSL/TLS configuration`
                    });
                });
            }

            this.addLog('INFO', 'SSL/TLS analysis completed');
        } catch (error) {
            this.addLog('ERROR', `SSL/TLS check failed: ${error.message}`);
        }
    }

    async discoverEndpoints(url) {
        try {
            // Common endpoints to check
            const commonEndpoints = [
                '/admin', '/login', '/api', '/api/v1', '/api/v2',
                '/dashboard', '/config', '/backup', '/test',
                '/robots.txt', '/sitemap.xml', '/.env', '/wp-admin',
                '/phpmyadmin', '/admin.php', '/config.php', '/info.php'
            ];

            const baseUrl = new URL(url).origin;
            
            for (const endpoint of commonEndpoints) {
                // Simulate endpoint discovery
                if (Math.random() > 0.7) {
                    const method = Math.random() > 0.5 ? 'GET' : 'POST';
                    const status = Math.floor(Math.random() * 400) + 200;
                    
                    this.results.endpoints.push({
                        url: baseUrl + endpoint,
                        method: method,
                        status: status,
                        discovered: true
                    });

                    // Check for sensitive endpoints
                    if (endpoint.includes('admin') || endpoint.includes('config') || endpoint.includes('.env')) {
                        this.results.vulnerabilities.push({
                            type: 'Information Disclosure',
                            severity: 'medium',
                            title: `Sensitive endpoint exposed: ${endpoint}`,
                            description: `A potentially sensitive endpoint was discovered that may contain administrative or configuration information.`,
                            details: `Endpoint: ${baseUrl + endpoint}\nMethod: ${method}\nStatus: ${status}\nRecommendation: Restrict access to sensitive endpoints`
                        });
                    }
                }
            }

            this.addLog('INFO', `Endpoint discovery completed. Found ${this.results.endpoints.length} endpoints`);
        } catch (error) {
            this.addLog('ERROR', `Endpoint discovery failed: ${error.message}`);
        }
    }

    async testSQLInjection(url) {
        try {
            // SQL injection payloads for testing
            const sqlPayloads = [
                "' OR '1'='1",
                "' UNION SELECT NULL--",
                "'; DROP TABLE users--",
                "' OR 1=1#",
                "admin'--"
            ];

            // Simulate SQL injection testing
            for (const payload of sqlPayloads) {
                if (Math.random() > 0.85) {
                    this.results.vulnerabilities.push({
                        type: 'SQL Injection',
                        severity: 'high',
                        title: 'Potential SQL Injection vulnerability',
                        description: 'The application appears to be vulnerable to SQL injection attacks.',
                        details: `Payload: ${payload}\nLocation: Query parameter\nRecommendation: Use parameterized queries and input validation`
                    });
                    break;
                }
            }

            this.addLog('INFO', 'SQL injection testing completed');
        } catch (error) {
            this.addLog('ERROR', `SQL injection testing failed: ${error.message}`);
        }
    }

    async testXSS(url) {
        try {
            // XSS payloads for testing
            const xssPayloads = [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "javascript:alert('XSS')",
                "<svg onload=alert('XSS')>",
                "';alert('XSS');//"
            ];

            // Simulate XSS testing
            for (const payload of xssPayloads) {
                if (Math.random() > 0.8) {
                    this.results.vulnerabilities.push({
                        type: 'Cross-Site Scripting (XSS)',
                        severity: 'high',
                        title: 'Potential XSS vulnerability detected',
                        description: 'The application may be vulnerable to Cross-Site Scripting attacks.',
                        details: `Payload: ${payload}\nType: Reflected XSS\nRecommendation: Implement proper input validation and output encoding`
                    });
                    break;
                }
            }

            this.addLog('INFO', 'XSS testing completed');
        } catch (error) {
            this.addLog('ERROR', `XSS testing failed: ${error.message}`);
        }
    }

    async testDirectoryTraversal(url) {
        try {
            // Directory traversal payloads
            const traversalPayloads = [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "....//....//....//etc/passwd",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
            ];

            // Simulate directory traversal testing
            for (const payload of traversalPayloads) {
                if (Math.random() > 0.9) {
                    this.results.vulnerabilities.push({
                        type: 'Directory Traversal',
                        severity: 'high',
                        title: 'Directory traversal vulnerability detected',
                        description: 'The application may allow unauthorized access to files outside the web root.',
                        details: `Payload: ${payload}\nRecommendation: Implement proper input validation and file access controls`
                    });
                    break;
                }
            }

            this.addLog('INFO', 'Directory traversal testing completed');
        } catch (error) {
            this.addLog('ERROR', `Directory traversal testing failed: ${error.message}`);
        }
    }

    async checkCSRF(url) {
        try {
            // Simulate CSRF protection check
            const hasCSRFToken = Math.random() > 0.6;
            const hasSameSiteCookie = Math.random() > 0.5;

            if (!hasCSRFToken) {
                this.results.vulnerabilities.push({
                    type: 'CSRF',
                    severity: 'medium',
                    title: 'Missing CSRF protection',
                    description: 'The application does not appear to implement CSRF tokens for state-changing operations.',
                    details: 'CSRF Token: Not found\nRecommendation: Implement CSRF tokens for all state-changing requests'
                });
            }

            if (!hasSameSiteCookie) {
                this.results.vulnerabilities.push({
                    type: 'CSRF',
                    severity: 'low',
                    title: 'Missing SameSite cookie attribute',
                    description: 'Cookies do not have the SameSite attribute set, which may help prevent CSRF attacks.',
                    details: 'SameSite Attribute: Missing\nRecommendation: Set SameSite=Strict or SameSite=Lax on cookies'
                });
            }

            this.addLog('INFO', 'CSRF protection check completed');
        } catch (error) {
            this.addLog('ERROR', `CSRF check failed: ${error.message}`);
        }
    }

    async testAuthBypass(url) {
        try {
            // Simulate authentication bypass testing
            const bypassAttempts = [
                'SQL injection in login form',
                'Default credentials check',
                'Session fixation test',
                'Password reset bypass'
            ];

            for (const attempt of bypassAttempts) {
                if (Math.random() > 0.95) {
                    this.results.vulnerabilities.push({
                        type: 'Authentication Bypass',
                        severity: 'critical',
                        title: `Authentication bypass via ${attempt}`,
                        description: 'A potential authentication bypass vulnerability was detected.',
                        details: `Method: ${attempt}\nRecommendation: Review authentication implementation and fix identified issues`
                    });
                }
            }

            this.addLog('INFO', 'Authentication bypass testing completed');
        } catch (error) {
            this.addLog('ERROR', `Authentication bypass testing failed: ${error.message}`);
        }
    }

    getScanOptions() {
        return {
            sqlInjection: document.getElementById('sql-injection').checked,
            xss: document.getElementById('xss').checked,
            directoryTraversal: document.getElementById('directory-traversal').checked,
            csrf: document.getElementById('csrf').checked,
            securityHeaders: document.getElementById('security-headers').checked,
            sslTls: document.getElementById('ssl-tls').checked,
            endpointDiscovery: document.getElementById('endpoint-discovery').checked,
            authBypass: document.getElementById('auth-bypass').checked
        };
    }

    updateScanButton(scanning) {
        const button = document.getElementById('start-scan');
        if (scanning) {
            button.disabled = true;
            button.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Scanning...';
        } else {
            button.disabled = false;
            button.innerHTML = '<i class="fas fa-search"></i> Start Scan';
        }
    }

    showProgress() {
        document.getElementById('progress-container').classList.remove('hidden');
    }

    hideProgress() {
        document.getElementById('progress-container').classList.add('hidden');
    }

    updateProgress(percentage, text) {
        document.getElementById('progress-fill').style.width = percentage + '%';
        document.getElementById('progress-text').textContent = text;
    }

    clearResults() {
        this.results = {
            vulnerabilities: [],
            endpoints: [],
            headers: {},
            logs: []
        };
        this.updateDisplay();
    }

    updateOverview() {
        const vulnCount = this.results.vulnerabilities.length;
        const endpointCount = this.results.endpoints.length;
        
        // Calculate risk level
        const criticalVulns = this.results.vulnerabilities.filter(v => v.severity === 'critical').length;
        const highVulns = this.results.vulnerabilities.filter(v => v.severity === 'high').length;
        
        let riskLevel = 'Low';
        let riskColor = '#27ae60';
        
        if (criticalVulns > 0) {
            riskLevel = 'Critical';
            riskColor = '#e74c3c';
        } else if (highVulns > 0) {
            riskLevel = 'High';
            riskColor = '#e67e22';
        } else if (vulnCount > 0) {
            riskLevel = 'Medium';
            riskColor = '#f39c12';
        }

        document.getElementById('scan-status-text').textContent = 'Completed';
        document.getElementById('vuln-count').textContent = vulnCount;
        document.getElementById('endpoint-count').textContent = endpointCount;
        document.getElementById('risk-level').textContent = riskLevel;
        document.getElementById('risk-level').style.color = riskColor;

        this.updateDisplay();
    }

    updateDisplay() {
        this.displayVulnerabilities();
        this.displayEndpoints();
        this.displayHeaders();
        this.displayLogs();
    }

    displayVulnerabilities() {
        const container = document.getElementById('vuln-results');
        
        if (this.results.vulnerabilities.length === 0) {
            container.innerHTML = '<p>No vulnerabilities detected.</p>';
            return;
        }

        container.innerHTML = this.results.vulnerabilities.map(vuln => `
            <div class="vulnerability-item ${vuln.severity}">
                <div class="vuln-title">${vuln.title}</div>
                <div class="vuln-description">${vuln.description}</div>
                <div class="vuln-details">${vuln.details}</div>
            </div>
        `).join('');
    }

    displayEndpoints() {
        const container = document.getElementById('endpoint-results');
        
        if (this.results.endpoints.length === 0) {
            container.innerHTML = '<p>No endpoints discovered.</p>';
            return;
        }

        container.innerHTML = this.results.endpoints.map(endpoint => `
            <div class="endpoint-item">
                <div class="endpoint-url">${endpoint.url}</div>
                <span class="endpoint-method method-${endpoint.method.toLowerCase()}">${endpoint.method}</span>
                <span>Status: ${endpoint.status}</span>
            </div>
        `).join('');
    }

    displayHeaders() {
        const container = document.getElementById('header-results');
        const headers = this.results.headers;
        
        if (Object.keys(headers).length === 0) {
            container.innerHTML = '<p>No header information available.</p>';
            return;
        }

        container.innerHTML = Object.entries(headers).map(([header, value]) => `
            <div class="vulnerability-item ${value ? 'info' : 'medium'}">
                <div class="vuln-title">${header}</div>
                <div class="vuln-description">${value ? 'Present' : 'Missing'}</div>
                <div class="vuln-details">Value: ${value || 'Not set'}</div>
            </div>
        `).join('');
    }

    displayLogs() {
        const container = document.getElementById('log-results');
        
        if (this.results.logs.length === 0) {
            container.innerHTML = '<p>No logs available.</p>';
            return;
        }

        container.innerHTML = this.results.logs.map(log => `
            <div class="log-entry">
                <span class="log-timestamp">${log.timestamp}</span>
                <span>[${log.level}]</span>
                <span>${log.message}</span>
            </div>
        `).join('');
    }

    switchTab(tabName) {
        // Remove active class from all tabs and panes
        document.querySelectorAll('.tab-button').forEach(btn => btn.classList.remove('active'));
        document.querySelectorAll('.tab-pane').forEach(pane => pane.classList.remove('active'));
        
        // Add active class to selected tab and pane
        document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');
        document.getElementById(tabName).classList.add('active');
    }

    addLog(level, message) {
        const timestamp = new Date().toLocaleTimeString();
        this.results.logs.push({
            timestamp,
            level,
            message
        });
        
        // Update logs display if currently visible
        if (document.getElementById('logs').classList.contains('active')) {
            this.displayLogs();
        }
    }

    isValidUrl(string) {
        try {
            new URL(string);
            return true;
        } catch (_) {
            return false;
        }
    }

    delay(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
}

// Initialize the scanner when the page loads
document.addEventListener('DOMContentLoaded', () => {
    new SecurityScanner();
});
