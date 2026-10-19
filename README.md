# MirageProxy

MirageProxy is a custom-built tunneling tool designed to obscure and relay traffic through Deep Packet Inspection (DPI) systems and network observers.

Instead of exposing a standard proxy port, MirageProxy wraps all your traffic inside standard, TLS-encrypted HTTPS requests. It uses long-lived streaming HTTP responses (`/poll`) and chunked POST requests (`/upload`) to tunnel your data. To any network observers, it looks exactly like you are browsing a normal HTTPS website, syncing enterprise data, or streaming media.

### Features
* **HTTP Streaming:** Uses NDJSON over a keep-alive HTTP connection for low-latency downstream traffic. Note that throughput is modest by design: Base64 encoding (+33%), JSON framing, and per-POST overhead all add cost. It is fine for browsing, SSH, and everyday use, but it is not a high-bandwidth link.
* **Standard CA Trust:** By default, the client enforces strict TLS verification, expecting a valid enterprise certificate (like Cloudflare or Let's Encrypt). This makes MITM attacks by intercepting networks impossible.
* **HMAC Authentication:** Every request is signed with a rolling timestamp and a build-time injected secret. Port scanners get a fake 404 page, and captured traffic replayed hours later falls outside the signature's 90-second window.
* **Active Probe Defense:** Unauthorized requests or scanners are immediately served a fake `nginx/1.18.0` 404 page.
* **TLS Fingerprint Spoofing:** Uses `uTLS` to masquerade the client's TLS `ClientHello` signature as a standard Google Chrome browser, defeating client fingerprinting.

---

## Architecture Diagram

Here is a high-level overview of how MirageProxy encapsulates and routes your traffic:

```text
       [ Web Browser / Application ]
                   │
                   │ (SOCKS5 Traffic - Port 1080)
                   ▼
     ┌───────────────────────────┐
     │ Shadowsocks Local         │ (Local SOCKS5 translation)
     └─────────────┬─────────────┘
                   │
                   │ (Encrypted Payload)
                   ▼
     ┌───────────────────────────┐
     │ MirageProxy Client        │ (Wraps in JSON + Base64, signs HMAC)
     └─────────────┬─────────────┘
                   │
                   │ (Standard HTTPS/TLS Traffic - Port 443)
                   │ (Mimics enterprise API syncing)
 ══════════════════╪══════════════════
    [ Strict DPI / Network Monitor ]
 ══════════════════╪══════════════════
                   │
                   ▼
     ┌───────────────────────────┐
     │ CDN / Reverse Proxy       │ (Optional - e.g., Cloudflare)
     └─────────────┬─────────────┘
                   │
                   ▼
     ┌───────────────────────────┐
     │ MirageProxy Server (VPS)  │ (Verifies HMAC, unwraps JSON/Base64)
     └─────────────┬─────────────┘
                   │
                   ▼
     ┌───────────────────────────┐
     │ Shadowsocks Server        │ (Relays data to the internet)
     └─────────────┬─────────────┘
                   │
                   ▼
          [ Global Internet ]
```

---

## Design Philosophy: Resilient Engineering & Steganography

Restrictive network environments and advanced DPI systems frequently target standard tunneling protocols (like WebSockets or gRPC) using Traffic Flow Security (TFS) analysis. A continuous stream of uninterrupted binary data stands out to network monitors.

MirageProxy takes a different approach: **Steganographic API Mimicry** and **Collateral Freedom**. It intentionally trades raw protocol efficiency for absolute statistical camouflage against well-funded network filters.

* **Blending Into Ordinary Traffic:** Advanced firewalls use Shannon entropy heuristics to flag fully encrypted payloads (which look like pure white noise). To counter this, MirageProxy encodes the stream in Base64 (slightly lowering entropy) and wraps it in standard JSON, so the traffic profile resembles mundane enterprise API calls. To be clear, this is statistical camouflage, **not** encryption: a middlebox that reassembles and deep-parses individual HTTP requests *can* recognize the pattern. The goal is to look ordinary enough to pass generic mass filtering, not to defeat an adversary that has decided to analyze your traffic specifically.
* **Hiding in the Noise (Collateral Freedom):** By using chunked HTTP POSTs and long-polling GETs, MirageProxy mimics the exact behavior of mundane, legacy enterprise REST APIs, telemetry uploads, or corporate data syncs. If a network filter aggressively blocks this traffic profile, they risk breaking legitimate traffic.
* **Defeating Active Probes:** Network scanners frequently send malformed TCP packets or garbage HTTP requests to suspected proxy ports to see how the server responds. MirageProxy drops these instantly and serves a flawless `nginx/1.18.0` 404 Not Found page, tricking network scanners into categorizing the server as an abandoned web host.
* **Replay Resistance:** Observers sometimes capture packets and replay them minutes or hours later to map server behavior. MirageProxy signs every request with an HMAC-SHA256 signature over a rolling timestamp (`X-Auth-Time` / `X-Auth-Sig`), so replays outside the 90-second window are rejected and served the fake Nginx 404 page. Note the limit: there is no nonce cache, so a captured request replayed *within* that 90-second window would still be accepted. The window bounds the usefulness of a replay rather than eliminating it.
* **Defeating MITM Attacks:** Intercepting parties sometimes attempt Man-In-The-Middle attacks by presenting fake SSL certificates. Because MirageProxy is designed to run behind a standard reverse proxy or CDN, the client strictly enforces standard CA verification. Any MITM attempt will immediately terminate the connection.
* **Shadowsocks Layering (Optional):** MirageProxy handles the *transport and stealth*, while Shadowsocks handles the *proxying*. The shipped configs use Shadowsocks in plaintext relay mode (`"method": "none"`), so the only encryption on your traffic is the TLS of the HTTPS tunnel itself — a single encryption layer by default. If you want genuine defense-in-depth, set a real AEAD cipher on both ends (for example `"method": "chacha20-ietf-poly1305"` with a strong password in both `sslocal-config.json` and `ssserver-config.json`); the tunnel will carry that extra encrypted layer transparently.

---

## Wire Protocol Details

Both directions move self-describing **parts**: JSON objects carrying `client_id`, `request_id`, `seq` (the stream sequence number), `part`/`total_parts` (fragment indices within one sequence), and a base64 `data` payload. Because every part identifies itself, sequences can be fired and delivered out of order and still be reassembled at the destination.

**Upstream (`POST /upload`):** The client pushes every outgoing part into a single global queue, and a pool of dispatcher workers drains it. Each worker gathers parts from *any* active connection into one batch of up to ~16KB (`{"parts":[...]}`) and fires it immediately; when the queue is empty it rechecks every 7ms. The server replies `200` with a bitmap — `{"acked":"11010"}` — one `'0'`/`'1'` bit per part in batch order. Acked parts are retired; unacked parts are requeued at the front of the queue (so gaps fill first) and retried up to 5 times, after which the originating local connection is torn down. Because the signature identity for uploads is the client (`upload-<clientid>`) rather than a single request, one POST can carry parts of many concurrent sessions.

**Downstream (`GET /poll`):** NDJSON, one `part` object per line (split at 8KB). All sessions feed a single global queue on the server, which a router goroutine fans out into per-client buffers drained by each client's long-poll connection.

**Piggybacked downstream:** `/upload` responses can also carry an optional `downstream` array of parts (up to 8KB of payload, drained non-blockingly from the same per-client buffer). This gives download traffic a second delivery lane riding on upload round-trips — useful when the poll stream momentarily falls behind (e.g. the browser reads slowly while other requests keep uploading) or while the poll connection is reconnecting. Each part is consumed by exactly one lane, so ordering and delivery guarantees are unchanged; when the poll stream keeps up on its own, upload responses simply carry nothing extra.

**Ordering & backpressure:** Neither side requires in-order delivery. Each direction keeps a 32-sequence reorder window: parts of future sequences are buffered, and data is only written to the local end once the head sequence is fully assembled (cascading through any complete sequences behind it). Flow control is pure backpressure — a full queue blocks the producing read loop on every hop (`sslocal → client → server → ssserver`), so nothing is ever dropped; the client additionally caps each connection at 32 sequences sent-but-unacked. A finalized session drains its window (with a short grace period) before closing, so the final marker can never race past in-flight parts.

---

## 1. Server Setup (VPS)

You will need a Linux machine with **Docker** installed.

### Step 1: Clone the repository
Clone this repository to your VPS (it includes the required config files):
```bash
git clone https://github.com/YOUR_USERNAME/mirageproxy.git
cd mirageproxy
```

### Step 2: Build the Docker Image
During the build process, a secure proxy secret is automatically generated and permanently paired between the server and client.

Set the `REMOTE_SERVER_URL` to the domain or IP you plan to connect to (refer to Step 4 below for deployment options):
```bash
# Example: Using a CDN domain or Secure Tunnel (Options A & B)
sudo docker build --build-arg REMOTE_SERVER_URL="https://proxy.yourdomain.com" -t mirageproxy .

# Example: Using Direct IP for testing (Option C)
# sudo docker build --build-arg REMOTE_SERVER_URL="https://YOUR_VPS_IP:30001" -t mirageproxy .
```

### Step 3: Run the Server
Start the Docker container.

**If port 443 is free:**
```bash
sudo docker rm -f mirageproxy || true
sudo docker run -d -p 443:30001 --restart always --name mirageproxy mirageproxy
```

**If port 443 is taken (e.g., you already host a website):**
Run the container on an alternate port like `8443`.
```bash
sudo docker run -d -p 8443:30001 --restart always --name mirageproxy mirageproxy
```

### Step 4: Choose and Configure Your Deployment
Now that the container is running locally on your VPS, you need to expose it to the internet. MirageProxy is highly flexible and supports multiple deployment architectures. Choose the one that fits your security needs:

**Option A: CDN Reverse Proxy (Highly Recommended)**
This method provides the best steganography. The network observer sees you connecting to a trusted CDN IP with a valid enterprise certificate.
1. **DNS Setup:** Go to your CDN provider (e.g., Cloudflare) and create an `A` record pointing `proxy.yourdomain.com` to your VPS's public IP address.
2. **Enable Proxying:** Ensure the traffic is being proxied through the CDN (e.g., ensure the "Orange Cloud" is toggled ON in Cloudflare).
3. **SSL/TLS Configuration:** Go to your CDN's SSL/TLS settings and set the encryption mode to **Full** (not "Strict"). This is required because the MirageProxy Docker container generates a self-signed certificate internally, which the CDN needs to accept.
4. **Port Forwarding:** If you ran the container on an alternate port (like `8443` in Step 3), ensure your CDN is configured to forward traffic to that specific port. In Cloudflare, this may require setting up an Origin Rule to map standard 443 traffic to your custom port.

**Option B: Secure Tunnel (Zero Open Ports / High Security)**
This method uses a service like Cloudflare Tunnels (`cloudflared`) to connect your VPS to the edge network. You do not need to open *any* inbound ports on your server's firewall, making it invisible to active port scanners.
1. **Install Daemon:** Download and install the `cloudflared` daemon on your Linux VPS.
2. **Authenticate:** Run `cloudflared tunnel login` to authenticate the server with your Cloudflare account.
3. **Create and Route:** Create a new tunnel and route your domain (e.g., `proxy.yourdomain.com`) to the MirageProxy container. Assuming you mapped port `443` in Step 3, you would route the tunnel to `https://localhost:443`.
4. **Disable TLS Verification:** Because the container uses an internal self-signed cert, you must configure the tunnel's origin server settings to enable `No TLS Verify` (or set the `no-tls-verify` flag in your `config.yml`).
5. **Run the Tunnel:** Run `cloudflared service install` to install the tunnel as a background system service so it survives reboots.

**Option C: Direct IP / Local Testing (No Domain Required)**
Use this if you are testing locally or don't have a domain name. You will connect directly to the VPS IP (or `127.0.0.1`).
1. **Configure Firewall:** You must open the port you selected in Step 3 on your VPS firewall to allow incoming connections. For example, if using UFW on port 443: `sudo ufw allow 443/tcp`.
2. **Client Flag:** Because you are connecting directly without a trusted CDN certificate acting as a front, you **must** run the client (in the later steps) with the `-insecure` flag. This tells your local machine to bypass standard TLS verification and accept the container's raw self-signed certificate.

---

## 2. Client Setup (Your PC)

Clone this repository on your local machine to access the config files and helper scripts. If you are using Windows, you should do this in WSL.

### Step 1: Extract the paired client binary
Because the client and server share a unique cryptographic secret generated at build time, you **must** download the specific client binary compiled inside your Docker container.

Run this on your **VPS** to extract the binary:
```bash
sudo docker cp mirageproxy:/app/client ./mirageproxy_client
```
*(Download `./mirageproxy_client` from your VPS to your local PC, and make it executable with `chmod +x mirageproxy_client`)*

### Step 2: Download Shadowsocks-Rust (Local)
On your local machine, you need `sslocal` to handle the local SOCKS5 translation. Run the provided helper script:

```bash
chmod +x grab_sslocal.sh
./grab_sslocal.sh
```
*(This will automatically download and extract the correct `sslocal` binary).*

---

## 3. Running the Proxy

You need to run both the MirageProxy client and `sslocal` on your local machine.

### Terminal 1: Start the MirageProxy Client
**If you are using a CDN or Secure Tunnel (Options A & B):**
```bash
./mirageproxy_client
```
*(The client will strictly verify that the server presents a valid, globally trusted SSL certificate).*

**If you are testing Locally / Using Direct IP (Option C):**
```bash
./mirageproxy_client -insecure
```
*(The `-insecure` flag tells the client to accept the internal self-signed Docker certificate. Use this for `127.0.0.1` testing).*

### Terminal 2: Start Shadowsocks Local
```bash
./sslocal -c sslocal-config.json
```
*(This listens on port `1080` and forwards standard SOCKS5 traffic into the MirageProxy HTTPS tunnel).*

---

## 4. Testing the Connection

You can now use any browser or tool that supports SOCKS5. To test via command line:

```bash
curl -v -L --proxy socks5h://127.0.0.1:1080 https://www.google.com
```

### Browser Setup (Firefox / Chrome)
* **Firefox:** Go to Settings -> Network Settings. Select "Manual proxy configuration". Set SOCKS Host to `127.0.0.1` and Port to `1080`. Check "Proxy DNS when using SOCKS v5".
* **Chrome/Edge:** It is highly recommended to use an extension like **SwitchyOmega** to route your traffic through `127.0.0.1:1080`.

## Troubleshooting

* **CDN SSL Settings:** If using a CDN, ensure your SSL/TLS encryption mode is set to **Full** (not Strict), so the CDN accepts the container's internal self-signed cert.
* **Hanging on `SOCKS5 request granted`:** Ensure your `mirageproxy_client` is running, and that your VPS firewall allows inbound TCP traffic on the port you exposed.
* **Logs:** If you are experiencing issues, edit the `.go` source files and change `const DebugMode = false` to `true`. Rebuild the container to see detailed chunk-level data transfer logs.
* **Server Logs:** View the server's background activity by running `sudo docker logs -f mirageproxy` on your VPS.
