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
        - http://badips.example.com/ip-blocklist
      ipallowlisturls:
        - http://badips.example.com/ip-allowlist
      useragentblocklisturls:
        - http://badips.example.com/useragent-blocklist
```

Optional settings:

| Key | Default | Meaning |
|-----|---------|---------|
| `cachedir` | *(none)* | Directory where the last good copy of every list and a pre-merged snapshot are kept. With it, a restart filters from the first request (the snapshot loads in milliseconds). Without it, requests pass unfiltered until the first download completes. |
| `refreshinterval` | `1h` | How often the lists are downloaded again (minimum `1m`). |

## Allow/Block lists

The allowlists and blocklists should be acccessible via http/s and be a plain text list of IP address or useragents. Blank lines and `#` comments are ignored; a malformed line is skipped and counted instead of failing the whole list.

## Loading behaviour

Traefik creates one middleware instance per router and recreates all of them on every configuration change. Instances with the same configuration share one copy of the lists, so the lists are downloaded and parsed once per process rather than once per router per reload, and `New` never waits for the network:

* Lists load from `cachedir` synchronously (milliseconds) and refresh from the network in the background, at start and every `refreshinterval`.
* A feed that fails to download, or returns an empty body, keeps its last good copy; the other feeds still refresh. A feed outage never disables the routers that use the middleware.
* Addresses are matched with a binary search over merged ranges, so the per-request cost does not grow with the size of the lists.

The plugin packs IPv4 ranges into `int` and refuses to start on 32-bit platforms.

## Testing

Running `go test` will run a set of unit tests. Running `docker compose up` will start an end to end testing environment where `allowed-*` containers should be able to make requests, while `blocked-*` containers should fail.
