# yt-proxy

Run one or more rotating WireGuard HTTP proxies in Docker.

## Routes and rotation

One route is one container, one active VPN tunnel, and one simultaneous exit
IP. Multiple configs in a route directory are alternative IPs used one at a
time by `/rotate`.

To use several exit IPs simultaneously, create several routes with separate
provider credentials. The number of active routes must stay within your VPN
plan's connection limit.

## Setup

Install Docker Compose and [uv](https://docs.astral.sh/uv/), then:

```bash
uv sync
```

Download WireGuard `.conf` files from your VPN provider and arrange them by
route:

```text
configs/provider/route-1/server-a.conf
configs/provider/route-1/server-b.conf
configs/provider/route-2/server-a.conf
```

Configure the host ports and matching routes in `fleet.yaml`:

```yaml
host_proxy_port_start: 8888
host_admin_port_start: 9888

routes:
  - name: vpn-1
    config_dir: provider/route-1
  - name: vpn-2
    config_dir: provider/route-2
```

Here, `vpn-1` and `vpn-2` can run simultaneously. Calling `/rotate` on `vpn-1`
switches between the configs in `provider/route-1`.

If another user runs a fleet on the same machine, choose different proxy and
admin port ranges. Compose project names include the current user ID by default,
so users do not manage each other's containers.

### Example: Proton VPN

In your Proton VPN account, open **Downloads → WireGuard configuration** and
download GNU/Linux configs for the servers you want to use:
<https://protonvpn.com/support/wireguard-configurations/>

Put configs for the first route in `configs/proton/route-1/`. For another
simultaneous route, generate separate configs and put them in
`configs/proton/route-2/`.

## Run

```bash
./spawn.sh plan
./spawn.sh up
```

The first route uses proxy port `8888` and admin port `9888`; each additional
route increments both ports.

```bash
curl -x http://127.0.0.1:8888 https://ifconfig.me
curl http://127.0.0.1:9888/status
curl -X POST http://127.0.0.1:9888/rotate \
  -H 'Content-Type: application/json' \
  -d '{"reason":"manual"}'
```

Rotating changes the WireGuard config and exit IP behind the proxy. The proxy
URL stays the same.

## yt-dlp example

```bash
yt-dlp --proxy http://127.0.0.1:8888 \
  'https://www.youtube.com/watch?v=VIDEO_ID'
```

If the exit IP starts failing, rotate it and retry:

```bash
curl -X POST http://127.0.0.1:9888/rotate \
  -H 'Content-Type: application/json' \
  -d '{"reason":"yt-dlp failure"}'

yt-dlp --proxy http://127.0.0.1:8888 \
  'https://www.youtube.com/watch?v=VIDEO_ID'
```

Port `8888` is the HTTP proxy. Port `9888` is the admin API and should not be
passed to `yt-dlp`.

## Docker clients

Start the proxies on a named network:

```bash
./spawn.sh up --network my-app-net
```

Add `my-app-net` as an external network in the client's Compose file, or attach
an already-running container:

```bash
./spawn.sh up --network my-app-net --attach-container my-app
```

From that network, the first route is available at:

```text
proxy: http://proxy-vpn-1:8888
admin: http://proxy-vpn-1:8889
```

```bash
yt-dlp --proxy http://proxy-vpn-1:8888 \
  'https://www.youtube.com/watch?v=VIDEO_ID'
```

## Operations

```bash
./spawn.sh ps
./spawn.sh logs -f
./spawn.sh down
```

The host must provide `/dev/net/tun` and allow Docker to grant `NET_ADMIN`.
