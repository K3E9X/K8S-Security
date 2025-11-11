# Security Policy

## Reporting Security Issues

**Please do not report security vulnerabilities through public GitHub issues.**

If you discover a security vulnerability in this training repository (such as exposed credentials in examples, unsafe lab configurations, or documentation that could lead to security misconfigurations), please report it responsibly.

### Reporting Process

Send an email to: **security@example.com**

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if applicable)

You should receive a response within 48 hours. We will keep you updated on the remediation progress.

## Scope

This repository contains:
- **Training Materials**: Documentation and educational content
- **Lab Examples**: Code meant for learning environments only
- **Tool Configurations**: Example security tool setups

### In Scope
- Exposed secrets or credentials in examples
- Labs that could create insecure cluster configurations
- Documentation promoting insecure practices
- Vulnerable dependencies in lab automation
- XSS or injection vulnerabilities in web components

### Out of Scope
- Issues with third-party tools (report to respective projects)
- General questions about Kubernetes security (use GitHub Discussions)
- Feature requests (use GitHub Issues)

## Security Best Practices

### For Lab Environments

All labs in this repository are designed for local development clusters. They should:
- **Never** be used in production without significant hardening
- Use placeholder credentials and secrets
- Include cleanup instructions
- Document security implications

### Warning Labels

Labs with elevated privileges or security implications are marked:

```
⚠️ SECURITY WARNING: This lab demonstrates privilege escalation.
Only run in isolated test environments.
```

## Supported Versions

We support security updates for the current major version and provide guidance for:

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Vulnerability Disclosure Timeline

1. **Day 0**: Report received
2. **Day 1-2**: Initial response and triage
3. **Day 3-7**: Investigation and fix development
4. **Day 7-14**: Testing and validation
5. **Day 14**: Public disclosure and fix release

Critical vulnerabilities may have accelerated timelines.

## Security Updates

Security fixes are released as patch versions and documented in:
- CHANGELOG.md
- GitHub Security Advisories
- Release notes

Subscribe to repository notifications for security updates.

## Recognition

We appreciate security researchers who report vulnerabilities responsibly. With your permission, we will:
- Credit you in CHANGELOG.md
- Mention you in security advisory
- Add you to SECURITY.md acknowledgments

## Acknowledgments

Thanks to the following security researchers:
- (Names will be added as reports are received and resolved)

## Additional Resources

- [Kubernetes Security Best Practices](https://kubernetes.io/docs/concepts/security/)
- [CNCF Security TAG](https://github.com/cncf/tag-security)
- [CWE: Common Weakness Enumeration](https://cwe.mitre.org/)

---

*Last updated: November 2025*
