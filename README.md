# Landlock tutorial to patch lighttpd

Network access-control is well covered by different kind of firewalls, but for some use cases it may be interesting to tie the semantic of an application instance and its configuration to a set of rules. For instance, only some processes of web browsers or web servers may legitimately be allowed to share data over the network, while other processes should be blocked. Linux provides some mechanisms to do so, including SELinux or AppArmor, but until now it has not been possible for applications to safely sandbox themselves.

This tutorial will first introduce Landlock, the new Linux sandboxing feature, which currently only supports filesystem access. We will then talk about a new set of access rights that are being developed to restrict TCP, which will also be an opportunity to discuss network restrictions that might come next. This will allow us to patch a simple network application (written in C) to make it sandbox itself following a best-effort approach.

Slides: [How to sandbox a network application with Landlock](2022-10-24_netdevconf-landlock.pdf)

Event: [Netdev Conference 0x16](https://netdevconf.info/0x16/session.html?How-to-sandbox-a-network-application-with-Landlock)
