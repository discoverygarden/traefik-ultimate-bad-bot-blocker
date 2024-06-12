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
```

## Blocklist

The blocklists should be acccessible via http/s and be a plain text list of IP address.
