# traceroute

A traceroute implementation written in Go, built over ICMP. Give it a hostname and it prints the route your packets take to get there.

This is a learning project. The goal is to understand how packets travel across the internet.

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

## Example Output

```text
$ sudo go run . google.com

Hop 1:
  192.168.68.1                     7.036459ms
  192.168.68.1                     6.86175ms
  192.168.68.1                     7.918291ms
Hop 2:
  csp3.zte.com.cn. (192.168.1.1)   12.467583ms
  csp3.zte.com.cn. (192.168.1.1)   7.52825ms
  csp3.zte.com.cn. (192.168.1.1)   9.215208ms

... hops 3-16 omitted ...

Hop 17:
  any-in-2678.1e100.net. (216.239.38.120) 19.8245ms
  any-in-2678.1e100.net. (216.239.38.120) 18.042458ms
  any-in-2678.1e100.net. (216.239.38.120) 18.84675ms
```
