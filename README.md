# ipsec_ikev2-debian
IPSec IKEv2 Roadwarior Automatic Setup Bash Script

This script can be useful for setting up IPSec server with Strongswan + IKEv2 + key authentication (Roadwarrior).
It allows users to get secure access to another network over an unsecure network (Internet).
It also routes Internet traffic through the tunnel.

It has been written for my own personal use for the following setup, where the VPN server is behind a router and is NATted.
The ports should be redirected on the router.
There are so many possible scenarios of setting up StrongSwan with IKEv2. This script focuses on one of them.

I hope it's going to be useful.
