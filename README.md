# syn-scan

Small, simple utility written in Go that scans a TCP port service on a target by using the half-open syn scanning method.


## Usage example and how to compile it from source

```bash
git clone https://github.com/hoenirvili/syn-scan
cd syn-scan
go build
./syn-scan google.com 80 # Should return open
```

### FAQ

1) Why not use nmap?

Ofcourse use nmap, there's not any single reason to not use nmap instead of this.

2) Why you wrote this?

For fun tbh and I wanted to see how hard is to craft hand made packets and send them over the wire using Go as a language
