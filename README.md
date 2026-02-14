# traceroute

Traceroute written in Go

## Usage

```bash
# Default: 3 probes, 5 second wait, 64 max hops, with address-to-name lookup
sudo go run . google.com

# Custom: 2 probes, 2 second wait, 20 max hops, skip address-to-name lookup
sudo go run . -q 2 -w 2 -m 20 -n google.com
```

## Options

- `-q`: Number of probes per hop (default 3)
- `-w`: Time (in seconds) to wait for a response to a probe (default 5)
- `-m`: Max time-to-live (max number of hops) (default 64)
- `-n`: Print hop addresses numerically (skip address-to-name lookup) (default false)
