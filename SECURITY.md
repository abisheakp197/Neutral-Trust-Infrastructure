# Security Policy

## Supported Versions

We actively maintain and patch the latest release of the NTI core cryptographic engine.

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

This repository contains the foundational cryptographic primitives for the NTI ecosystem, including Post-Quantum signatures (Dilithium5) and Key Encapsulation Mechanisms (Kyber1024). We take memory safety, zeroization, and constant-time execution extremely seriously.

Please report vulnerabilities directly to **abisheakp197@gmail.com**.

You should receive a response within 48 hours. If for some reason you do not, please follow up via email to ensure we received your original message.

Please include the following information in your report:
*   Type of issue (e.g., buffer overflow, timing attack, missing zeroization, PyO3 binding flaw)
*   Full paths of source file(s) related to the manifestation of the issue
*   The location of the affected source code (tag/branch/commit or direct URL)
*   Any special configuration required to reproduce the issue
*   Step-by-step instructions to reproduce the issue

We will investigate all legitimate reports and do our best to quickly fix the problem.
