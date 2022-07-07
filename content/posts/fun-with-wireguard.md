---
title: "Fun With Wireguard"
date: 2021-03-30T21:12:25-05:00
lastmod: 2021-11-03T21:12:25-05:00
draft: false

# HelloFriend Specific
hideReadMore: false
#cover = "img/default.jpg"
#description = "description"
---

After a recent conversation I realized that some folks have a narrow view of what can be done 
with Wireguard, and VPN connections in general. Though recently a number of toolsets/frameworks 
tailored for networking of containers or "bolt on zero-trust" networking have expanded that 
perception. My goal with this post is to highlight some software leveraging Wireguard, and to 
list a few different use-cases and reasons for using Wireguard (over traditional VPN or 
ZeroTier).


## Use Cases
* Meshed networking of disparate peers. 
* Exposing internal network applications to the internet without port forwarding.
* Exposing web apps with a reverse proxy to Wireguard network clients.
* Point-to-point VPN for connected sites.
* Non-forwarded Wireguard connection for LAN gaming and resource sharing.
* Resilient VPN for mobile devices, capable of handling network hopping.

## Software Leveraging Wireguard

### Innernet
[innernet](https://blog.tonari.no/introducing-innernet) is an opensource alternative to Tailscale 
or ZeroTier that can create a secure networks with minimal management overhead. 

### Tailscale
[Tailscale](https://tailscale.com/) is a zero config VPN with firewall rule management, allowing 
for a secure network layer on top of existing infrastructure.

### Firezone
[Firezone](https://github.com/firezone/firezone) is a Linux package to manage your WireGuard VPN and Linux firewall from a simple web interface.

### PiVPN
[PiVPN](https://www.pivpn.io/) is an absolutely simple deployment and management script for 
Wireguard, well suited for a Raspberry Pi and other light weight deployments, with its simplicity 
taking after that of the [Pi-Hole](https://pi-hole.net/) project.

### Algo by Trail of Bits
[Algo](https://github.com/trailofbits/algo) is a set if Ansible deployment scripts for building a 
personal Wireguard (or IPsec) VPN with support for many common cloud providers.


## Personal Uses
My most recent uses of Wireguard is with a non-forwarded client setup, creating a loose mesh network for devices on different LANs to communicate; and in some cases using a Nginx reverse proxy on the Wireguard VPN server to expose internal web applications to the internet.

Aside from a standard VPN or the above mesh, I've found that Wireguard works exceptionally on my 
phone. I can switch between cellular and WiFi without any noticed drops. And with mobile carriers 
getting heavy handed with "anonymized" data collection, ads, and apps heavy with telemetry; 
having an always on Wireguard VPN with Pi-Hole serving up DNS for the clients, I can audit and 
block access to unwanted resources.
