1. End-to-End Flow
Mac host
 ↓
Create Ubuntu VM with Multipass
 ↓
Validate OS + CPU architecture + systemd 
 ↓
Copy install.sh and capture.service 
 ↓
Create CompliWise agent / obtain enrollment values
 ↓
Create /etc/compliwise/capture.env
 ↓
Install Capture binary
 ↓
Configure systemd to load capture.env
 ↓
Start Capture
 ↓
Enroll with CompliWise
 ↓
Heartbeat accepted / discovery scan posted
 ↓
Certificate discovery tests

2. Create a Clean VM
Run these commands on the Mac host.

multipass launch --name certwisetest01 --cpus 2 --memory 2G --disk 10G

Purpose: creates and starts an Ubuntu VM with 2 vCPUs, 2 GB RAM, and a 10 GB disk.

multipass list

Purpose: verifies that the VM exists, is running, and has an IP address.

multipass shell certwisetest01
Purpose: opens a shell inside the Ubuntu VM.

3. Baseline Validation

cat /etc/os-release
Confirms the Linux distribution and version.

uname -m
Confirms CPU architecture. In this test, the result was aarch64.

ps -p 1 -o comm=
Confirms PID 1 is systemd. Expected result: systemd.

sudo systemctl status capture
On a clean VM, 'Unit capture.service could not be found' is expected and confirms no previous installation.

4. Architecture Support Validation
The installer was inspected to confirm ARM64 support:
grep -n -E 'aarch64|arm64|x86_64|amd64|ARCH' install.sh

Observed mapping:
x86_64)         
ARCH="amd64" ;; aarch64|arm64)  
ARCH="arm64" ;;

Therefore an aarch64 VM is supported by this installer, and it downloads the linux_arm64 release artifact.

5. Copy Installation Files to the VM
From the Mac, go to the repository's Linux deployment folder, then:
multipass exec certwisetest01 -- mkdir -p /home/ubuntu/compliwise-linux

multipass transfer install.sh capture.service certwisetest01:/home/ubuntu/compliwise-linux/

Inside the VM:
cd ~/compliwise-linux ls -la
Expected files: install.sh and capture.service.

6. Enrollment Configuration
Create a protected environment file for the CompliWise connection. Use values generated for the same agent registration in the UI. Enrollment codes are one-time/time-limited and should be generated immediately before enrollment.

sudo mkdir -p /etc/compliwise
sudo nano /etc/compliwise/capture.env

Template (placeholders only):
API_SECRET=<local-api-secret>
COMPLIWISE_API_URL=<compliwise-api-url>
COMPLIWISE_ORG_ID=<organization-id>
COMPLIWISE_AGENT_ID=<agent-id>
COMPLIWISE_ENROLLMENT_CODE=<fresh-one-time-enrollment-code>
COMPLIWISE_POLL_INTERVAL=60

sudo chmod 600 /etc/compliwise/capture.env
Purpose: restricts the environment file to root read/write access.

7. Install the Capture Binary

From ~/compliwise-linux:
sudo ./install.sh

The installer detects architecture, fetches the latest release, downloads the appropriate archive, extracts Capture, installs the binary to /usr/local/bin/capture, creates a systemd service, enables it, and starts it.

ls -l /usr/local/bin/capture

This must show an executable file. If it does not exist, systemd will fail with status 203/EXEC.

8. Configure systemd for CompliWise Enrollment

The tested installer generated its own /etc/systemd/system/capture.service and did not automatically retain the custom EnvironmentFile line. After installation, edit the installed unit:

sudo nano /etc/systemd/system/capture.service

Under [Service], ensure these relevant settings are present:
ExecStart=/usr/local/bin/capture
WorkingDirectory=/usr/local/bin
EnvironmentFile=/etc/compliwise/capture.env
ProtectSystem=strict
ReadWritePaths=/etc/compliwise

EnvironmentFile loads the enrollment variables. ReadWritePaths=/etc/compliwise allows the agent to persist agent.env while ProtectSystem=strict keeps the rest of the protected filesystem read-only for the service.
Do not leave template placeholders such as YOUR_PATH/capture, User=user_name, or Group=group_name in the installed unit.

9. Reload and Start systemd

sudo systemd-analyze verify /etc/systemd/system/capture.service
sudo systemctl daemon-reload
sudo systemctl enable capture
sudo systemctl restart capture
sudo systemctl status capture --no-pager -l

daemon-reload makes systemd reread changed unit definitions; enabling the service configures it to start with the normal multi-user boot target. systemd documentation recommends daemon-reload after relevant unit/configuration changes. 


10. Validate the Local Agent

curl http://localhost:59232/health
Expected response: "OK". This proves the local HTTP service is reachable.

The metrics endpoint requires Bearer authentication:
curl -i \
  -H "Authorization: Bearer <API_SECRET>" \
    http://localhost:59232/api/v1/metrics
401 indicates a missing/incorrect Authorization header format. 403 indicates the Bearer header was parsed but the token did not match the configured API_SECRET.

11. Validate Enrollment and Heartbeat

sudo journalctl -u capture -n 50 --no-pager
Successful validation observed during testing included messages equivalent to:
certiwise: control plane enabled (...)
certiwise: enrolled agent <agent-id> with CompliWise API certiwise: heartbeat status=online
certiwise: heartbeat accepted for agent <agent-id>
certiwise: discovery: posted scan
These messages prove that the agent can reach the control plane, authenticate/enroll, send an online heartbeat, and submit discovery data.

12. Certificate Discovery Test Plan

After installation/enrollment is stable, test certificate discovery systematically. Start with one simple certificate, confirm discovery in the agent logs/UI, then repeat with application runtimes.

Create or install a known test certificate on the VM.

Record its subject/common name, issuer, serial number, validity dates, file/store location, and expected application.

Trigger or wait for the Capture discovery scan.

Confirm the certificate appears in the CompliWise UI with correct metadata.

Repeat for Java keystore/truststore scenarios.

Repeat for Python TLS/certificate usage.

Repeat for a C/OpenSSL-based application.

Repeat for COBOL/runtime-specific certificate stores where applicable.

Test certificate replacement/renewal and confirm the platform detects the updated certificate.




CompliWise Synthetic Monitor
Cloudflare Tunnel Test Setup

End-to-End Lab Procedure and Troubleshooting Guide

Purpose. Document the complete test used to expose a TLS endpoint running inside a local Multipass Ubuntu VM to the public CompliWise worker through a Cloudflare Quick Tunnel, validate network/TLS connectivity, and configure a CompliWise synthetic HTTPS monitor.
==============================================================================
CompliWise Synthetic Monitor
Cloudflare Tunnel Test Setup
===============================================================================


1. Architecture and Why the Original Test Failed

The Ubuntu VM is hosted locally on the Mac. The Mac and VM do not need to have the same IP address. Multipass creates a virtual network and the Mac has a route to the VM through bridge100.

Observed addresses:

Mac Wi-Fi IP: 192.168.1.99

VM IP:       192.168.252.8

The Mac can still reach 192.168.252.8 because macOS routes the 192.168.252.x virtual network through the bridge100 interface. This was confirmed with:

route -n get 192.168.252.8
netstat -rn | grep 192.168.252

A local connectivity test also succeeded on TCP port 8443:

nc -vz 192.168.252.8 8443

However, the CompliWise cloud worker is outside this local virtual network. The private address 192.168.252.8 is not publicly routable, so the worker cannot directly reach https://192.168.252.8:8443. This is a network reachability problem before certificate/TLS validation can be useful.

2. Test TLS Endpoint in the Ubuntu VM

The test certificate and private key were stored under ~/server-tls-test:

ls -l ~/server-tls-test/tls.crt ~/server-tls-test/tls.key

The files observed during testing were tls.crt and tls.key. Run the OpenSSL server from that directory:

cd ~/server-tls-test
openssl s_server -accept 8443 -cert tls.crt -key tls.key -www

Successful startup output observed:
Using default temp DH parameters
ACCEPT

If OpenSSL reports 'Address already in use', another process is already listening on 8443. Check it with:

sudo ss -lntp | grep 8443

During the test, port 8443 was already owned by an openssl process. Do not start a second server unless the existing process is intentionally stopped.

Required sequence: start OpenSSL first and keep that terminal running; verify port 8443 is listening; then perform the local curl test. Only after the local endpoint returns HTTP 200 should cloudflared be started.

3. Validate the Endpoint Locally

Run this command inside the Ubuntu VM, not on the Mac, because 127.0.0.1 always refers to the machine where the command is executed:

curl -vk https://127.0.0.1:8443

Successful output showed a TLS 1.3 handshake, the self-signed certificate with CN=certwisetest01, and HTTP/1.0 200. The -k option is required for this lab because the certificate is self-signed.

From the Mac, use the VM address instead:

curl -vk https://192.168.252.8:8443

This also returned HTTP 200 and confirmed that Mac -> bridge100 -> VM -> port 8443 connectivity was working.

4. Install Cloudflared in the VM

The following commands were used in the Ubuntu VM:

sudo mkdir -p --mode=0755 /usr/share/keyrings

curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg \
  | sudo tee /usr/share/keyrings/cloudflare-main.gpg >/dev/null

echo "deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared any main" \
  | sudo tee /etc/apt/sources.list.d/cloudflared.list

sudo apt-get update
sudo apt-get install cloudflared

cloudflared --version

Cloudflared 2026.8.2 was installed successfully. The apt output also reported that the VM clock/repository metadata had a 'not valid yet' warning and that a newer kernel was pending. These messages did not prevent cloudflared itself from installing.

5. Create a Public Cloudflare Quick Tunnel

With the OpenSSL service reachable on 127.0.0.1:8443, start the tunnel in a separate VM terminal:

cloudflared tunnel --url https://127.0.0.1:8443 --no-tls-verify

The --no-tls-verify option tells cloudflared not to reject the self-signed certificate presented by the local OpenSSL origin. The Quick Tunnel then provides a public HTTPS hostname.

The final tunnel created during this test was:

https://revolutionary-dig-cornell-fort.trycloudflare.com

Cloudflared reported successful DNS resolution, QUIC connectivity, HTTP/2 connectivity, Cloudflare API reachability, and a registered tunnel connection. Keep this cloudflared process running while testing.

6. Validate the Public URL

From the Mac, test the public hostname:

curl -vk https://revolutionary-dig-cornell-fort.trycloudflare.com

Expected successful behavior is an HTTP 200 response through Cloudflare and the OpenSSL test page from the VM.

7. Important 530 and 502 Troubleshooting

Symptom

Meaning in this test

Action

HTTP 530 / Cloudflare error 1033

The old Quick Tunnel hostname no longer had an active tunnel connection.

Start cloudflared again and use the newly generated trycloudflare.com hostname.

HTTP 502 Bad Gateway

Cloudflare/tunnel was reachable, but cloudflared could not successfully reach the local origin.

Verify curl -vk https://127.0.0.1:8443 inside the VM, then restart the tunnel.

Connection refused on 127.0.0.1:8443

Nothing is listening on loopback port 8443 at that moment.

Check sudo ss -lntp | grep 8443 and start/fix the OpenSSL server.

Address already in use

A process is already bound to port 8443.

Use sudo ss -lntp | grep 8443. Do not launch a duplicate listener.

Quick Tunnel hostnames are temporary. If cloudflared is stopped and a new Quick Tunnel is started, a new hostname may be generated. The CompliWise monitor must then be updated to the new hostname.

8. Configure the CompliWise Synthetic Monitor

Use the public Cloudflare hostname, not the private VM IP.

Endpoint: URL: https://revolutionary-dig-cornell-fort.trycloudflare.com; HTTP method: GET; Authentication: None.

Monitoring: Select the CompliWise worker/location and the required schedule. During this test the monitor showed a 5-minute interval.

Validation: Expected HTTP status: 200. Set a response-time threshold appropriate for the test. An earlier 1000 ms threshold caused a Degraded result when the response took 1183 ms.

Test check: Run the one-off probe. A successful public path should return HTTP 200. Then save/update the monitor.

9. Understanding CompliWise Status

Immediately after monitor creation, CompliWise displayed the monitor as Healthy but Configuration health as Warning with the message: 'Awaiting first check — worker probes run on the next scheduled tick.'

This warning does not by itself mean the endpoint is failing. It means the scheduled worker has not yet produced the first monitor result. Until that happens, fields such as HTTP status, response time, certificate expiry, and last checked can remain N/A or blank.

Keep both the OpenSSL origin and cloudflared tunnel running and wait for the next scheduled check.

Final Sequential Runbook - Exact Order

10. End-to-End Traffic Flow

CompliWise Cloud Worker
        |
        | HTTPS to public hostname
        v
Cloudflare Edge
        |
        | Active Cloudflare Tunnel
        v
cloudflared inside Ubuntu VM
        |
        | HTTPS to 127.0.0.1:8443
        v
OpenSSL s_server
        |
        v
tls.crt / tls.key
 





