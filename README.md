# Traefik Bad Bot Blocker

Traefik Plugin based on the [Apache Ultimate Bad Bot Blocker](https://github.com/mitchellkrogza/apache-ultimate-bad-bot-blocker/tree/master).

## Configuration

Middleware example:
```yaml
---
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: botblocker
spec:
  plugin:
    botblocker:
      ipblocklisturls:
        - http://badips.example.com/ip-blocklist"
      ipwhitelisturls:
        - https://apacheconfblacklist.s3.us-east-1.amazonaws.com/whitelist
      useragentblocklisturls:
        - http://badips.example.com/useragent-blocklist"
```

## Blocklist

The blocklists should be acccessible via http/s and be a plain text list of IP address or useragents.

## Whitelist

`ipwhitelisturls` takes the same kind of plain text list of IPs/CIDRs, fetched over http/s on the same hourly refresh as the blocklists. A request from an IP matched by the whitelist is passed straight through: neither the IP blocklists nor the user agent blocklists are consulted for it.

Blank lines and `#` comments are ignored in IP lists.

## Testing

Running `go test` will run a set of unit tests. Running `docker compose up` will start an end to end testing environment where `allowed-*` containers should be able to make requests, while `blocked-*` containers should fail.
