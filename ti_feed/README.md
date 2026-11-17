# ti_feed — Local IOC feed for QR Guard

This folder holds the **local threat-intelligence list** that the worker reads at startup.
Every file here except this README is generated, **never commit it** (it is in `.gitignore`).

| File | Contents |
|---|---|
| `ioc_feed.jsonl` | One indicator per line (domain or exact URL) |
| `ioc_feed.meta.json` | Sources, licences, download time, counts, SHA-256 (cite this in the report) |

## Build / refresh

```powershell
# Phishing.Database only (no account needed)
python scripts/build_ioc_feed.py --write-env

# + URLhaus (free abuse.ch Auth-Key stored in secrets/urlhaus_auth_key)
python scripts/build_ioc_feed.py --urlhaus-key-file secrets/urlhaus_auth_key --write-env

# Load the new list into the worker
docker compose up -d processing-worker
```

`--write-env` pins the SHA-256 in `.env` (`TI_LOCAL_FEED_SHA256`). If the feed file is modified
afterwards, the worker refuses it (`integrity_failed`) instead of trusting tampered data.

Refresh at least weekly. Domain entries carry `last_seen` = download time; after
`TI_IOC_MAX_AGE_DAYS` (90) without a rebuild they become *stale* and only yield a medium warning.

## Sources and licences

| Source | Licence / terms | Used as |
|---|---|---|
| Phishing.Database `phishing-domains-ACTIVE.txt` | MIT | Domain indicators |
| URLhaus `recent.csv` (abuse.ch) | Free under abuse.ch fair-use principles; commercial use needs a Spamhaus subscription | Exact-URL indicators only |

## Safety filters applied by the builder

- Entries that **are** (or are a parent of) an official brand domain, a hosting platform, a URL
  shortener or a public suffix are dropped. In the real list `sites.google.com` and `telegra.ph`
  appear; without this filter every link on those platforms would be flagged malicious.
- Sub-domains of legitimate first-party services (`*.sharepoint.com`, `*.docs.google.com`…) are
  kept as **suspicious**, never "known malicious".
- Sub-domains on tenant platforms (`evil.web.app`, `x.github.io`) stay **phishing**, because the
  attacker controls them.
- URLhaus produces **exact URLs only**, because it lists many compromised legitimate sites.
