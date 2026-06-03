# Examples

## Basic Scan

```bash
python ssrf_arsenal.py --target example.com
```

## Target File

```bash
python ssrf_arsenal.py --target-file targets.txt
```

## Burp Collaborator

```bash
python ssrf_arsenal.py \
--target example.com \
--burp-collaborator abc.burpcollaborator.net
```

## Full Export

```bash
python ssrf_arsenal.py \
--target example.com \
--output reports \
--export-nuclei \
--export-siem \
--export-json-api \
--attack-map
```
