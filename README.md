# Landlock tutorial to patch lighttpd

Network access-control is well covered by different kind of firewalls, but for some use cases it may be interesting to tie the semantic of an application instance and its configuration to a set of rules. For instance, only some processes of web browsers or web servers may legitimately be allowed to share data over the network, while other processes should be blocked. Linux provides some mechanisms to do so, including SELinux or AppArmor, but until now it has not been possible for applications to safely sandbox themselves.

# Dependencies installation on the host

Run these commands as root in your main system:

## Arch Linux
```bash
# pacman -S vagrant libvirt base-devel dnsmasq
# systemctl enable --now libvirtd.service
```

See the [Arch Linux libvirt tutorial](https://wiki.archlinux.org/title/libvirt) for more details.

## Debian or Ubuntu
```bash
# apt install --no-install-recommends vagrant qemu-utils ruby-libvirt ruby-dev libvirt-daemon-system qemu-system
```

See the [Debian KVM tutorial](https://wiki.debian.org/KVM) for more details.

## Fedora
```bash
# dnf install vagrant qemu libvirt
# systemctl enable --now virtnetworkd
```

## Generic

If not already done, start libvirtd.
```bash
# systemctl start libvirtd.service
```

It is possible that your Linux distro don't configure your user for libvirt use by default.
If it's your case, you should configure it following your distro recommendations.

# VM Installation and configuration

As an unprivileged user, create the project using the tar archive:
```bash
$ git clone https://github.com/landlock-lsm/tuto-lighttpd
$ cd tuto-lighttpd
```

The Vagrant VM provisioning will install 3 vagrant plugins on your host, other commands are executed in the VM.
After plugins installation Vagrant will ask to execute the same command again to proceed the VM configuration.


```bash
$ vagrant up
```

A virbr<n> interface will be generated, you may need to allow inbound connections (and routing) from the loopback interface according to your firewall rules if needed.

# Connecting to the VM

```bash
$ vagrant ssh
```

# Testing the installation

On the VM, start the lighttpd service and check the logs:
```bash
$ sudo systemctl start lighttpd.service
$ sudo journalctl -fu lighttpd.service &
$ sudo tail -F /var/log/lighttpd/error.log &
```

Use the `getlink.sh` script to get the local website link.
```bash
$ /vagrant/getlink.sh
```

Visit the link with your web browser to validate that it works.
This link may change each time the VM starts.
