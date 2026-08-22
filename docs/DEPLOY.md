# Deploying AreYouSievious

Written for [Coolify](https://coolify.io), but everything outside the first
section applies to any Docker host behind a reverse proxy.

## Coolify

**New Resource → Public (or Private) Repository → Build Pack: `Dockerfile`.**

| Setting | Value |
|---|---|
| Build Pack | `Dockerfile` |
| Dockerfile location | `/Dockerfile` (repo root, the default) |
| Base directory | `/` |
| Port | `8091` |
| Health check path | `/healthz` |

Nothing else needs configuring. The image already builds the SPA, serves it
from the same origin as the API, runs as a non-root user under `tini`, and
carries its own `HEALTHCHECK`. Coolify's proxy terminates TLS and issues the
certificate; the container speaks plain HTTP on `8091` behind it.

Do **not** use the repo's `docker-compose.yml` for this. It publishes to
`127.0.0.1`, which Coolify's Traefik cannot reach — it exists for local
development only.

## Environment

### Required

| Variable | Value | Why |
|---|---|---|
| `AYS_ENV` | `prod` | Anything other than exactly `dev` keeps `/docs`, `/redoc` and `/openapi.json` closed. The default is already `prod`; set it so the intent is visible. |
| `AYS_SECURE_COOKIES` | `true` | Marks the session and CSRF cookies `Secure`. Coolify terminates TLS at its proxy and does not necessarily forward `X-Forwarded-Proto`, so the app cannot infer HTTPS on its own — this is the documented escape hatch for exactly that shape. |
| `AYS_TRUSTED_PROXIES` | `10.0.0.0/8,172.16.0.0/12` | **Read the section below before skipping this.** |

### Should set

| Variable | Value | Why |
|---|---|---|
| `AYS_CORS_ORIGINS` | `https://sieve.example.com` | Your domain. The SPA is served from the same origin as the API, so no preflight normally happens and this rarely bites — but the default names a domain that is not yours, and leaving it is a trap for whoever next runs the SPA from a separate origin. |

### Never in production

| Variable | Why not |
|---|---|
| `AYS_IMAP_INSECURE` | Skips outbound IMAP TLS verification. Leaves every login open to MITM credential theft (CWE-295). It exists for testing against a self-signed mail server and nothing else. |

Everything else has a working default. `README.md` has the full table.

## `AYS_TRUSTED_PROXIES`, and why an empty one is a footgun here

Unset means "trust no proxy headers", which is the correct and deliberate
default — honouring `X-Forwarded-For` from any caller is a way to walk
straight past the login throttle (CWE-348).

But with nothing trusted, the app falls back to the **direct peer** for the
client's identity. Behind a reverse proxy the direct peer is the proxy — the
same address for every request in the world. The login limiter allows 5
attempts per 5 minutes per client, so:

> Five failed logins by one stranger lock out **every user of the instance**
> for five minutes.

Nothing looks wrong while this is set up incorrectly. The app starts, serves
pages and throttles as designed; the symptom appears minutes later as "nobody
can log in". The app logs a warning at startup when the list is empty — if you
see this in Coolify's logs, this section is why:

```
AYS_TRUSTED_PROXIES is empty, so X-Forwarded-For is ignored and the login
rate limit is keyed on the direct peer. ...
```

Set it to the network your proxy sits on. Docker's default bridge networks
live in `172.16.0.0/12`; Coolify's own networks are usually `10.0.0.0/8`.
Setting both is fine, and is the value in the table above.

Do **not** widen it to `0.0.0.0/0`. That trusts the header from anyone, which
is the hole the setting exists to close.

## Two things that will surprise you

**Sessions are in memory. Every redeploy logs everyone out.** There is no
database and no volume to mount — that is deliberate, because a session holds
the user's mail password in plaintext for as long as it lives, and the store
that holds it should not outlive the process. Users log back in; nothing is
lost but the session itself.

**The mail server must be on a public address.** Outbound connections are
checked against an SSRF deny-list, so any host resolving to a private,
loopback, link-local or reserved address is refused with *"Connection to
private/internal addresses is not allowed"*. There is no override.

This means **a mail server on the same Coolify box, or on the same private
network, cannot be reached** — the guard cannot tell your mail server apart
from an attacker using this app to probe your internal network, which is the
attack it exists to stop. Point it at a publicly-resolvable hostname.

## Verifying a deploy

```bash
BASE=https://sieve.example.com

curl -s $BASE/healthz                     # {"status":"ok"}
curl -s $BASE/api/auth/status             # {"authenticated":false}
curl -so /dev/null -w '%{http_code}\n' $BASE/api/scripts    # 401

# The docs gate. NOTE: not a 404 — see below.
curl -s $BASE/openapi.json | head -c 40                     # <!doctype html ...
```

**`/openapi.json` returns `200`, and that is correct.** The SPA's catch-all
`GET /{full_path:path}` answers anything unmatched, so with `AYS_ENV=prod` the
schema route is not registered and the request falls through to the SPA shell
— the same `200 text/html` you get from any nonsense URL. The status code
cannot tell you whether the gate holds; the body can.

Gate holding (`AYS_ENV=prod`):

```
$ curl -s $BASE/openapi.json | head -c 40
<!doctype html>
<html lang="en">
```

Gate open (`AYS_ENV=dev`) — the real schema, as JSON:

```
$ curl -s $BASE/openapi.json | head -c 40
{"openapi":"3.1.0","info":{"title":"AreY
```

If you see JSON in production, `AYS_ENV` is not exactly `prod`.

`AYS_SECURE_COOKIES` cannot be checked with curl: cookies are set only by a
SUCCESSFUL login, so there is no unauthenticated response carrying one. Log in
through the browser and look at `ays_session` in devtools → Application →
Cookies. No `Secure` flag means the variable did not take, and the symptom to
expect is being logged straight back out — the browser will refuse to return
the cookie it was just given.

Also worth one look in Coolify's log view after the first boot: if the
`AYS_TRUSTED_PROXIES` warning quoted above is there, the throttle is keyed on
Traefik and the section above applies.

## Local development

`docker compose up --build` runs the same image bound to `127.0.0.1:8091`.
For the non-container loop, see the Commands section of `AGENTS.md`.
