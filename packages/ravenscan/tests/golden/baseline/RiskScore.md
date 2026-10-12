# Risk Score

**Scored:** <TS>
**Schema version:** 1
**Overall Score:** 72.5/100 — **Grade: C**

## Category Scores
| Category | Score | Trend |
|----------|-------|-------|
| architecture | 95.0 | N/A |
| security | 10.0 | N/A |
| maintainability | 100.0 | N/A |
| operational | 80.0 | N/A |
| documentation | 75.0 | N/A |
| testing | 50.0 | N/A |
| technical_debt | 95.0 | N/A |
| developer_experience | 75.0 | N/A |

### Architecture

Architecture score based on module structure, coupling, and code organization.

**Evidence:**
- Dead code: Potentially dead module: app

**Recommendations:**
- Remove or repurpose dead modules.

### Security

Security score based on detected vulnerabilities mapped to CWE.

**Evidence:**
- CWE-798: Hardcoded secret detected: API key literal
- CWE-327: Weak cryptography: MD5 hashing
- CWE-78: Potential command injection via os.system/os.popen
- CWE-95: Dangerous eval() call
- CWE-79: [JS/TS] .innerHTML assignment

**Recommendations:**
- Address all critical and high-severity findings immediately.
- Run security scans as part of CI/CD pipeline.

### Maintainability

Maintainability based on file sizes, module organization, and code structure.

**Evidence:**
- Code structure looks maintainable.

**Recommendations:**
- Split large files into smaller, focused modules.
- Keep average file size under 500 lines where practical.

### Operational

Operational score based on infrastructure configuration and runtime health.

**Evidence:**
- Docker: No
- CI/CD: No
- No Docker configuration detected.
- No CI/CD pipeline detected.

**Recommendations:**
- Add Docker support for consistent deployments.
- Set up CI/CD for automated testing and deployment.
- Run 'raven scan' from the deployment environment to include runtime operational health.

### Documentation

Documentation score based on presence of README, docs directory, and documentation files.

**Evidence:**
- Documentation files found: 1

**Recommendations:**
- 
- Maintain documentation in a docs/ directory.

### Testing

Testing score based on presence of test directory and test files.

**Evidence:**
- Test files found: 0

**Recommendations:**
- Add a tests/ directory with unit tests.
- Increase test coverage.

### Technical Debt

Technical debt score based on accumulated architecture issues.

**Evidence:**
- No significant technical debt indicators.

**Recommendations:**
- Refactor god modules into smaller, focused modules.
- Break circular dependencies.
- Remove dead code.

### Developer Experience

Developer experience based on CI, containerization, documentation, and code quality.

**Evidence:**
- Basic DX indicators met.

**Recommendations:**
- Set up CI/CD if not already configured.
- Add Docker support for consistent dev environments.
- Reduce TODO/FIXME count to improve code quality signal.
