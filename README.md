# n3recon-v2.1.sh

A comprehensive bash-based reconnaissance pipeline for security assessments. Automatically discovers subdomains, resolves DNS, probes HTTP endpoints, collects URLs, and scans for secrets.

## Features

- **Subdomain Enumeration** — Multiple sources: subfinder, assetfinder, findomain, sublist3r, chaos, crt.sh, github-subdomains, crobat, certspotter, bufferover, riddler, securitytrails
- **DNS Resolution** — Uses dnsx for fast resolution with collection of IP addresses
- **HTTP Probing** — httpx to identify alive web endpoints with status codes
- **URL Collection** — gau, waybackurls, katana, gospider, hakrawler for URL gathering
- **JS Discovery** — katana, subjs, getJS for JavaScript file discovery
- **Secret Scanning** — GF patterns, TruffleHog, SecretFinder, LinkFinder
- **Port Scanning** — naabu for quick port enumeration
- **OSINT** — theHarvester for email gathering, asnmap for ASN information
- **Screenshots** — gowitness for taking screenshots of alive hosts
- **Vulnerability Scanning** — nuclei integration (optional)
- **Directory Fuzzing** — ffuf integration (optional)

## Requirements

### Core Tools (in PATH)

```bash
# Install core Go-based tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/assetfinder/cmd/assetfinder@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/fuff/v2/cmd/fuff@latest
go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest
go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest

# Install other useful tools
go install github.com/tomnomnom/assetfinder@latest
go install github.com/tomnomnom/gf@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/tomnomnom/hakrawler@latest
go install github.com/Emoe/gau/v2/cmd/gau@latest
go install github.com/sullo/nikto@latest
go install github.com/OWASP/Amass/v3/...@latest
go install github.com/cgboal/sonarsearch/cmd/crobat@latest
go install github.com/projectdiscovery/uncover/cmd/uncover@latest
go install github.com/hahwul/dalfox/v2/cmd/dalfox@latest

# Install findomain
wget https://github.com/Edu4rdSHL/findomain/releases/latest/download/findomain-linux.zip
unzip findomain-linux.zip && chmod +x findomain && sudo mv findomain /usr/local/bin/

# Install Python tools
pip install sublist3r subdomainizer secretfinder linkfinder cloud_enum js-beautify

# Install additional tools
pip install pydictor || true
go install github.com/Josue87/gotator@latest
go install github.com/nyx0/gospider@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/003random/getJS@latest
go install github.com/jaeles-project/gospider@latest
go install github.com/hahwul/subjs@latest
go install github.com/0xDivy/anew@latest
go install github.com/tomnomnom/anew@latest
go install github.com/sullo/nikto@latest
go install github.com/hahwul/nofingerprint@latest
go install github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest

# Install trufflehog
go install github.com/trufflesecurity/trufflehog@latest

# Install gowitness
go install github.com/sensepost/gowitness@latest

# Install theHarvester
git clone https://github.com/laramies/theHarvester
cd theHarvester && pip install -r requirements.txt

# Install uro (URL deduplication)
pip install uro

# Install SecLists (wordlists)
git clone https://github.com/danielmiessler/SecLists /usr/share/wordlists/SecLists
```

## Usage

```bash
# Basic usage
./n3recon-v2.1.sh example.com

# Multiple domains
./n3recon-v2.1.sh example.com target.com

# From file
./n3recon-v2.1.sh --domains-file domains.txt

# Custom output directory
./n3recon-v2.1.sh example.com --output-dir /tmp/recon

# With API keys
./n3recon-v2.1.sh example.com --api-keys-file api-keys.yaml

# Only subdomain enumeration
./n3recon-v2.1.sh example.com --only-subdomains

# Skip certain stages
./n3recon-v2.1.sh example.com --skip-screenshots --skip-vuln-scan

# Resume previous run
./n3recon-v2.1.sh example.com --resume

# Force new run
./n3recon-v2.1.sh example.com --new

# Custom wordlist
./n3recon-v2.1.sh example.com --wordlist /path/to/wordlist.txt

# Exclude patterns
./n3recon-v2.1.sh example.com --exclude "test,staging"

# Whitelist only
./n3recon-v2.1.sh example.com --whitelist "prod,live"

# Recursive subdomain enumeration (brute force + permutations)
./n3recon-v2.1.sh example.com --recursive-subdomains
```

## Options

| Option | Description |
|--------|-------------|
| `--domains-file FILE` | Read domains from file (one per line) |
| `--output-dir DIR` | Set output directory (default: current directory) |
| `--resume` | Resume from latest run |
| `--new` | Force new run, ignore resume |
| `--threads N` | Number of threads (default: 200) |
| `--exclude` | Comma-separated strings or file to exclude |
| `--whitelist` | Comma-separated strings or file to whitelist |
| `--only-subdomains` | Stop after subdomain enumeration |
| `--skip-screenshots` | Skip screenshot stage |
| `--skip-vuln-scan` | Skip nuclei vulnerability scanning |
| `--skip-dir-fuzz` | Skip ffuf directory fuzzing |
| `--recursive-subdomains` | Use brute force and permutations |
| `--api-keys-file FILE` | Path to API keys config (YAML format) |
| `--wordlist FILE` | Path to wordlist for brute force |
| `-h, --help` | Show help |

## API Keys Configuration

Create a YAML file for API keys:

```yaml
# api-keys.yaml
chaos: key1,key2,key3
securitytrails: key1,key2
subfinder: /path/to/subfinder-config.yaml
```

Keys can be comma-separated for automatic rotation.

## Output Structure

```
.
├── example.com/
│   ├── run1/
│   │   ├── notes.txt
│   │   ├── subdomains/
│   │   │   ├── subfinder.txt
│   │   │   ├── assetfinder.txt
│   │   │   ├── sublist3r.txt
│   │   │   └── ...
│   │   ├── resolved.txt
│   │   ├── ips.txt
│   │   ├── alive/
│   │   │   ├── httpx.txt
│   │   │   ├── 200.txt
│   │   │   ├── 403.txt
│   │   │   └── ...
│   │   ├── urls/
│   │   │   ├── gau.txt
│   │   │   ├── wayback.txt
│   │   │   ├── katana.txt
│   │   │   └── ...
│   │   ├── js/
│   │   │   ├── js_urls_alive.txt
│   │   │   ├── js_content/
│   │   │   └── js_beautified/
│   │   ├── secrets/
│   │   │   ├── secrets.txt
│   │   │   ├── gf/
│   │   │   └── ...
│   │   ├── osint/
│   │   │   ├── emails.txt
│   │   │   ├── asn.txt
│   │   │   └── ...
│   │   ├── screenshots/
│   │   └── vuln/
│   │       └── nuclei/
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `THREADS` | 200 | Number of parallel threads |
| `OUT_ROOT` | . | Output root directory |
| `LOG` | /dev/null | Log file path |

## Notes

- Tools are auto-detected — if a tool isn't installed, it's skipped with a warning
- The script is portable and works on any machine with tools in `$PATH`
- Use `--resume` to continue interrupted scans
- Wordlist defaults to common locations if not specified

## Author

Created by @n3dir

## License

MIT