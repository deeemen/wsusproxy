# WSUS compatibitily proxy for Windows XP

## What
A MITM proxy server that :
- rewrites plain HTTP and HTTPS requests for Windows Update from `www.update.microsoft.com` to `fe2.update.microsoft.com/v6`;
- handles basic SOAP headers;
- handles BITS 1.0 range-request compatibility when accessing WU;
- reencrypts all HTTPS traffic with self-signed certificate;
- saves all HTTP\HTTPS requests\responses to disk for future analysis;

## Why
To access __some__ updates for Windows XP and few other legacy products directly from Windows Update while they are still available.

## How
1. Place arbitrary files into local/ folder for future convinience - they may be accessed later from client computer. Suggested files are `windowsupdateagent30-x86.exe`, `wumt_x86.exe`.
1. Start proxy, make sure port 10080 is open in network firewall and can be reached from client machine.
1. Open IE and disable SSLv2, enable TLSv1, set proxy settings for http and https to `$IP:10080` where "$IP" is the IP address of proxy server.
1. Open IE and navigate to `http://$IP:10080/server.crt`, save file. Navigate to `http://$IP:10080/wsus.bat`, save file. Replace "$IP" with IP address of proxy server.
1. Open mmc, add certificates snap-in for computer account (important). Add server.crt to trusted root CAs.
1. Open wsus.bat and make sure contents look ok. Run it.
1. install at least windows update agent version 6.2.29.0(`windowsupdateagent30-x86.exe`)
1. Check for updates with windows update minitool or trigger updates using `wuauclnt /detectnow`.


## Notes
1. If you need to use this proxy outside of your trusted LAN then generating your own self-signed certificate is a good idea.
1. If you wish to generate new self-signed certificate make sure to use SHA1 signature (for compatibility with WXP).
2. You can access modern SSL-protected websites from IE6 that utilize TLS1.2+,SNI and elliptic-curve cryptography. MITM will take care to talk to client only with SHA1+RSA TLS1.0-TLS1.1 and only with self-signed certificate that you added to trusted.
3. Caveat to MITM - it does not check validity of certificate that upstream server presents to wsusproxy - use at your own risk.
1. Files in `local/` directory are accessible from `http://$IP:10080/proxy-local/`
1. If you would like to configure WSUS manually then make sure to use `http://$IP:10080/wsus/` as server address.
1. When updating with MITM enabled every single HTTP(S) request-response is saved together with body, if any, into `dump/` folder. This in theory may permit to replay or reconstruct (partially, at least) update catalog from preserved copy.
1. Right now there is no convenient tool to parse and extract update binaries from preserved server responses in `dump/` folder - use full-text search in `meta.json` files and simply copy\rename `response` binary in the same folder.

## Thank you
- IMI Kurwica WSUS Proxy for inspiration and idea

Legal:
This software is provided without warranty of any kind. See LICENSE for details.
This software is not affiliated with Microsoft. Windows, Windows Update are (tm) Microsoft Corp.
