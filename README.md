# Traefik Bad Bot Blocker

Traefik Plugin based on the [Apache Ultimate Bad Bot Blocker](https://github.com/mitchellkrogza/apache-ultimate-bad-bot-blocker/tree/master). It blocks IP addresses, CIDR IP ranges and User-Agents from subscribed blocklists.

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
        - "https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/refs/heads/master/_generator_lists/bad-ip-addresses.list"
      useragentblocklisturls:
        - "https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/refs/heads/master/_generator_lists/bad-user-agents.list"
```

## Blocklists

The blocklists should be plain text list files of IP address, CIDR IP ranges or User-Agents that are acccessible via http/s.

This plugin is compatible with the generator lists of IP adresses, CIDR IP ranges and User-Agents from [Apache Ultimate Bad Bot Blocker](https://github.com/mitchellkrogza/apache-ultimate-bad-bot-blocker/tree/master/_generator_lists) and [NGINX Ultimage Bad Bot Blocker](https://github.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/tree/master/_generator_lists). The NGINX lists are preferred as they are updated more often. It is possible to subscribe to multiple lists, including the "good bots" allowlists should you want to deny them access to your services.

## Testing

Running `go test` will run a set of unit tests. Running `docker compose up` will start an end to end testing environment where `allowed-*` containers should be able to make requests, while `blocked-*` containers should fail.
