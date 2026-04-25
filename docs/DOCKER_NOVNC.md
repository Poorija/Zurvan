# Zurvan Docker + noVNC

This runtime keeps Zurvan as a desktop PyQt application. It does not convert the app to a web app. Docker runs a virtual Linux desktop with Xvfb, Openbox, x11vnc, and noVNC, then exposes that desktop through a browser.

## Build

```bash
docker compose -f docker-compose.novnc.yml build
```

## Run

```bash
docker compose -f docker-compose.novnc.yml up
```

Open:

```text
http://localhost:6080/vnc.html
```

Default application login:

```text
username: admin
password: P@ssw0rd1234567890
```

## Optional VNC Password

Set `VNC_PASSWORD` in `docker-compose.novnc.yml` to require authentication for both noVNC and raw VNC access.

## Ports

- `6080`: Browser access through noVNC.
- `5900`: Raw VNC access for a VNC client.

## Volumes

- `zurvan-data`: persistent app data.
- `zurvan-reports`: generated reports.
- `zurvan-artifacts`: package/audit outputs.

## Security Tool Limitations

Docker is a good packaging and desktop-delivery layer for Zurvan, but it is not identical to running a security workstation directly on the host.

- On Linux, `NET_ADMIN`, `NET_RAW`, and `seccomp:unconfined` help tools that need raw sockets.
- On Docker Desktop for macOS/Windows, packet capture, Wi-Fi monitor mode, host networking, and raw interface access are limited by the Linux VM boundary.
- Wireless tools generally require Linux with direct adapter passthrough.
- High-rate scans such as `masscan` are best run on Linux with explicit authorization and network scope.

## Useful Commands

```bash
docker compose -f docker-compose.novnc.yml ps
docker compose -f docker-compose.novnc.yml logs -f
docker compose -f docker-compose.novnc.yml down
```

To enter the running container:

```bash
docker compose -f docker-compose.novnc.yml exec zurvan-novnc bash
```
