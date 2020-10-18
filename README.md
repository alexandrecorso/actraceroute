# ACTraceroute

Network API tools like ping or traceroute

## Ping

Send ICMP packet to a destination. The destination is an IP or a domain.

```
/api/ping/4/{destination}
/api/ping/6/{destination}
```

## Traceroute

Trace to a destination. The destination is an IP or a domain.

Traceroute are available with
- ICMP
- UDP (not yet implemented)

```
/api/traceroute/4/{destination}
/api/traceroute/6/{destination}
```

2 others trace are available with asn lockup
```
/api/traceroute/4/asn/{destination}
/api/traceroute/6/asn/{destination}
```

## Docker

Build the image
```
docker build . -t acorso/actraceroute:latest
```

Run the image
```
docker run -d --net=host --name actrace acorso/actraceroute:latest
```