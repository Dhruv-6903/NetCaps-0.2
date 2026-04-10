# NetCaps-0.2

Desktop network forensics toolkit with phased architecture:

- Single-pass PCAP/PCAPNG processing
- Session + host tracking
- Artifact extraction (DNS/HTTP/FTP/SMTP, credentials, carved files)
- Alerting engine
- Indexed filtering + global search support
- PySide6 desktop UI (model/view tables, non-blocking worker updates)
- VirusTotal hash lookup queue
- CSV/JSON/HTML export and attack summary

## Quick start

```bash
python -m pip install -e .
netcaps /path/to/capture.pcap --export-dir exports --extracted-dir extracted
```

UI mode:

```bash
netcaps --ui
```

## Layout

- `src/netcaps/engine.py` – packet processing pipeline
- `src/netcaps/artifacts.py` – DNS/HTTP/FTP/SMTP parsers + file carving
- `src/netcaps/alerts.py` – detection rules
- `src/netcaps/store.py` – central case store + indexes
- `src/netcaps/ui.py` – desktop interface
- `src/netcaps/exporting.py` – CSV/JSON/HTML + summary exports
- `src/netcaps/virustotal.py` – asynchronous hash lookup queue
