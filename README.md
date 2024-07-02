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
      useragentblocklisturls:
        - http://badips.example.com/useragent-blocklist"
```

## Blocklist

The blocklists should be acccessible via http/s and be a plain text list of IP address or useragents.

## Testing

Running `got test` will run a set of unit tests. Running `docker compose up` will start an end to end testing environment where `allowed-*` containers should be able to make requests, while `blocked-*` containers should fail.
