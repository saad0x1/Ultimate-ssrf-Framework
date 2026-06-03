# Ultimate SSRF Framework v4.2 (Experimental)

## Demo

<div align="center">

![Ultimate SSRF Framework Demo](docs/demo.gif)

<br>

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)
![Version](https://img.shields.io/badge/Version-v4.2--experimental-orange.svg)
![Status](https://img.shields.io/badge/Status-Active-success.svg)
![CI](https://github.com/KauanCosta2000/Ultimate-ssrf-Framework/actions/workflows/python-ci.yml/badge.svg)

A framework for SSRF discovery, validation, and reporting, built for bug bounty hunting, penetration testing, and application security research.

</div>

---

> [!WARNING]
> This framework does not automatically prove exploitability or business impact.
>
> Findings should be reviewed and validated before disclosure or reporting.
>
> Blind SSRF confirmation relies on external OAST or Collaborator services.
>
> Some experimental modules may produce false positives.

## About

Ultimate SSRF Framework began as a collection of SSRF testing utilities used during bug bounty engagements.

Over time, additional functionality was added to cover common tasks such as endpoint discovery, blind SSRF validation, cloud metadata testing, infrastructure fingerprinting, and report generation.

The framework combines discovery, validation, testing, and reporting into a single command-line tool.

Its purpose is straightforward: reduce repetitive work and make SSRF testing easier to manage from start to finish.

---

## What it can do

### Discovery and Testing

* Endpoint discovery and crawling
* Blind SSRF validation
* Cloud metadata testing
* WAF fingerprinting
* File-based target scanning
* Multi-target scanning

### Advanced Modules

* WebSocket SSRF testing
* gRPC SSRF testing
* Kubernetes SSRF testing
* Serverless SSRF testing

### AI Features

* AI-assisted payload generation
* AI-assisted finding triage

### Reporting and Export

* HTML reporting
* JSON reporting
* Nuclei export
* SIEM (CEF) export
* Attack map generation

### Supported Cloud Providers

* AWS
* Azure
* Google Cloud Platform
* Alibaba Cloud

---

## Built-in Payloads

The framework includes a curated SSRF payload collection covering common testing scenarios.

Default payload categories include:

* Cloud metadata endpoints
* Localhost and loopback variants
* Internal network ranges
* Alternative IP encodings
* DNS helper domains
* Read-only file protocol checks
* Basic gopher and dict probes
* OAST callback validation

An optional aggressive mode enables additional protocol-specific payloads, including Redis write attempts and SMTP DATA probes.

> [!CAUTION]
> Aggressive payloads are disabled by default and should only be used in authorized testing environments.

---

## Reporting

The framework can generate:

* HTML reports
* JSON reports
* Nuclei templates
* SIEM CEF exports
* Attack maps

Use `--output` to define where generated files should be written.

Example output:

```text
reports/
├── ssrf_example.com_YYYYMMDD_HHMMSS.json
├── ssrf_report_example.com_YYYYMMDD_HHMMSS.html
├── nuclei_example.com.yaml
├── siem_example.com.cef
├── api_report_example.com.json
└── attack_map_example.com.gexf
```

---

## Development Status

The project is actively maintained and new modules are added as SSRF research and testing techniques evolve.

Current research areas include:

* WebSocket SSRF
* gRPC SSRF
* Kubernetes SSRF
* Serverless SSRF
* AI-assisted workflows

Several of these modules remain experimental and may change significantly between releases.

---

## Roadmap

Planned areas of development include:

* GraphQL SSRF discovery
* HTTP/2 request smuggling research
* DNS rebinding improvements
* Internal service fingerprinting
* Burp Suite extension
* OWASP ZAP integration
* Slack notifications
* Discord notifications

---

## Contributing

Bug reports, feature requests, pull requests, and research contributions are welcome.

Before opening a pull request, please review:

* `CONTRIBUTING.md`
* `SECURITY.md`

---

## Author

Developed by **Belladonnask**

* GitHub: https://github.com/KauanCosta2000
* LinkedIn: https://www.linkedin.com/in/kauan-costa-105b12345/

Licensed under the MIT License.

Copyright © Kauan Costa.

---

## Disclaimer

> [!CAUTION]
> This project is intended for authorized security testing, research, and educational use only.
>
> Users are responsible for ensuring that all testing activities comply with applicable laws and regulations.
>
> The authors and contributors assume no liability for misuse of this software.
