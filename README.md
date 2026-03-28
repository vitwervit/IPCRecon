# IPCRecon

Enumerate named pipes on remote Windows hosts via IPC$ and identify running software by pipe signatures.
 
Built-in database of **260+ patterns** covering EDR/AV, remote access tools, C2 frameworks, databases, and attack surface indicators — all categorized and attributed.

## Features
 
- **Categorized output**: offensive, attack surface, security/EDR, remote access, databases, monitoring, noise, Windows system
- **Attack surface detection**: highlights pipes indicating coercion/relay/privesc vectors (ADCS, Print Spooler, WebClient, EFS, Netlogon, DFS)
- **Smart defaults**: hides Windows system noise, shows everything interesting
- **Multi-auth fallback**: null session → Guest → credentials, with clear error messages
- **JSON output** for pipeline integration with `parallel`, `jq`, etc.
- **Extensible** via external JSON databases

## Quick Start
 
```bash
pip install -r requirements.txt
 
# Single host with credentials
python3 pipe_filter.py domain/user:password@10.0.0.5
 
# Null session
python3 pipe_filter.py @10.0.0.5
 
# Mass scan with GNU parallel
cat targets.txt | parallel -j 10 --timeout 30 --tag \
  python3 pipe_filter.py 'domain/user:pass@{}' 2>/dev/null
```

## Output Example
 
```
[*] Host: 192.168.10.10  (auth: credentials)
    Total pipes: 133  |  Shown: 14  |  Hidden: 119
 
  🔴 C2 / Offensive Tools  (1)
    ▸ PSEXESVC  ← Sysinternals PsExec
 
  🟡 Unidentified (investigate!)  (1)
    ● idodfopwgixcxchnnish
 
  ⚔  Attack Surface (coercion/relay/privesc)  (2)
    ▸ spoolss  ← Print Spooler → SpoolSample coercion, PrintNightmare
    ▸ cert     ← ADCS (Certificate Services) → ESC
 
  🛡  Security / EDR / AV  (7)
    ○ Kaspersky Endpoint Security  (5 pipes)
    ○ kscipc\15052  [Kaspersky Security Center (KSC)]
    ○ kscipc\3880   [Kaspersky Security Center (KSC)]
 
  🖥  Remote Access / VPN  (3)
    ○ OutlineServicePipe       [Outline VPN]
    ○ TightVNC_Service_Control [TightVNC]
    ○ TVN_log_pipe_public_name [TightVNC]
 
  Hidden: 🪟 Windows System (default): 32, ⚙ Runtime / Drivers / Noise: 88
  Use -show-windows to show Windows pipes, -show-noise to show runtime/drivers
```
## Visibility Controls
 
```bash
# Show default Windows pipes
python3 pipe_filter.py ... -show-windows
 
# Show runtime/driver noise (Chromium, .NET, printers...)
python3 pipe_filter.py ... -show-noise
 
# Show ONLY security and C2 categories
python3 pipe_filter.py ... -only security c2
 
# Hide specific categories
python3 pipe_filter.py ... -hide database other
 
# JSON output
python3 pipe_filter.py ... -json
```

## Extending the Database
 
Create a JSON file with additional patterns:
 
```json
{
    "pipes": [
        {"pattern": "MyCorpAgent",  "software": "Corp Agent", "category": "security",  "type": "exact"},
        {"pattern": "^CorpVPN_",    "software": "Corp VPN",   "category": "remote",    "type": "regex"}
    ]
}
```
 
Categories: `windows`, `security`, `remote`, `c2`, `attack`, `database`, `monitoring`, `noise`, `other`
 
```bash
python3 IPCRecon.py ... -known-db my_extra_pipes.json
```


## Acknowledgments

- Pattern database inspired by [tothi/serviceDetector](https://github.com/tothi/serviceDetector),
  [SigmaHQ](https://github.com/SigmaHQ/sigma) (DRL 1.1),
  [mthcht/awesome-lists](https://github.com/mthcht/awesome-lists)
- Built with [impacket](https://github.com/fortra/impacket) (Apache 2.0)
