# IPCRecon

Enumerate named pipes on a remote Windows host via IPC$,
identify software by pipe signatures and display structured results.

Default output hides only base Windows pipes. Everything else is shown,
grouped by category: Security, Remote Access, Offensive, Databases, etc.

## Example
```
python3 IPCRecon.py domain/user:password@target
python3 IPCRecon.py domain/user:password@target -show-windows
python3 IPCRecon.py domain/user:password@target -hide noise
python3 IPCRecon.py domain/user@target -hashes :NTHASH -json
python3 IPCRecon.py domain/user@target -k -dc-ip 10.0.0.1
```

## Acknowledgments

- Pattern database inspired by [tothi/serviceDetector](https://github.com/tothi/serviceDetector),
  [SigmaHQ](https://github.com/SigmaHQ/sigma) (DRL 1.1),
  [mthcht/awesome-lists](https://github.com/mthcht/awesome-lists)
- Built with [impacket](https://github.com/fortra/impacket) (Apache 2.0)
