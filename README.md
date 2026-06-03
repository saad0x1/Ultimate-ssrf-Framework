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

Created and maintained by **belladonnask**.

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

`not_confirmed` does not mean the target is safe. It only means the scanner did not confirm SSRF for that specific endpoint, parameter and payload.

Reports may include tested payloads, callback domains, internal IP references and scanned URLs. Review generated files before sharing them publicly.

---

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
* SIEM CEF export
* GEXF attack map generation
* Proxy support

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

The framework can generate multiple report formats for different workflows.

Supported outputs:

```text
.json   Full scan data, including endpoints, evidence, callbacks and tested payloads
.html   Human-readable report with findings and payload attempts
.cef    SIEM-friendly CEF export
.gexf   Attack map graph for visualization tools such as Gephi
.md     Optional AI triage summary when AI is enabled
```

The report tracks each tested payload and classifies every attempt as:

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

## Helper Scripts

The repository may include helper scripts for common workflows.

Basic scan:

```bash
./basic_scan.sh
```

Proxy scan:

```bash
./proxy_scan.sh
```

AI scan:

```bash
./ai_scan.sh
```

Export-focused scan:

```bash
./export_scan.sh
```

Example with custom variables:

```bash
TARGET=example.com CALLBACK=your-callback.oastify.com ./basic_scan.sh
```

Sheep AI helper example:

```bash
AI_PROVIDER=sheep AI_MODEL=hunter AI_KEY="$SHEEP_TOKEN" ./ai_scan.sh
```

---

## Testing

Run syntax check:

```bash
python -m py_compile ssrf_arsenal.py
```

Run tests:

```bash
python -m pytest -v
```

GitHub Actions can be used to run CI automatically on push and pull requests.

---

## Development Status

The project is actively maintained and new modules are added as SSRF research and testing techniques evolve.

Current research areas include:

* WebSocket SSRF
* gRPC SSRF
* Kubernetes SSRF
* Serverless SSRF
* AI-assisted workflows
* Sheep AI integration
* Payload attempt tracking
* Multi-format reporting

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
* Better AI-assisted triage templates
* Better report diffing between scans

---

## Contributing

Bug reports, feature requests, pull requests, and research contributions are welcome.

Before opening a pull request, please review:

* `CONTRIBUTING.md`
* `SECURITY.md`

---

## Limitations

* The scanner cannot prove that a target is safe.
* Lack of callback does not prove lack of SSRF.
* Some findings may be false positives and require manual validation.
* Some applications block outbound requests or sanitize payloads before execution.
* Some modules are experimental and may require tuning.
* AI output may be incomplete, noisy or wrong.
* Payload behavior should be reviewed before testing sensitive environments.

---

## Responsible Use

This project is intended for:

* Authorized penetration testing
* Bug bounty programs where testing is allowed
* Internal security assessments
* Controlled lab environments
* Research and learning

Do not use this tool against systems without permission.

---

## Author

Developed by **Belladonnask**

* GitHub: https://github.com/KauanCosta2000
* LinkedIn: https://www.linkedin.com/in/kauan-costa-105b12345/

Licensed under the MIT License.

Copyright © Kauan Costa.

See the repository license file for details.

---

## Disclaimer

> [!CAUTION]
> This project is intended for authorized security testing, research, and educational use only.
>
> Users are responsible for ensuring that all testing activities comply with applicable laws and regulations.
>
> The authors and contributors assume no liability for misuse of this software.
