# SecTorPi

## A Reasonably Secure Raspberry Pi 3 Tor Access Point ( or the Onion Router )

![Onion Router](https://github.com/d3cod3/SecTorPi/raw/master/img/onion-router.jpg)

[![ko-fi](https://www.ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/V7V21B90C)


Table of Contents
=================

  * [Description](#description)
  * [Install](#install)
  * [Post-Install Config](#post-install-config)
  * [Configuration](#configuration)
    * [Users](#users)
    * [SSH](#ssh)
    * [APT sources](#apt-sources)
    * [Encryption](#encryption)
    * [Net](#net)
    * [Tor](#tor)
    * [DNSCrypt](#dnscrypt)


# Description

There are a lot of tutorials over the web about bulding yout RPi onion router, some outdated, some perfectly working, and this one is just another one trying to explain in details all the steps, plus adding some security enhancement to the overall process.
Using Tor for anonymously browse the web can be done in different ways, depending on your skillsets, specific needs and paranoia levels, and, as always, there is not a better solution for everyone, it will always depends of every user needs. This approach, the **RPi Onion Router** one, is not the best one/highest security level, in terms of "apocalyptic paranoia" needs, but is way better than download the Tor Browser in your computer and use it while posting on Instagram.

Everyone have the right to anonymize his/her internet life, so let's do that properly, or at least just learn something from trying.

# Install

### 1 - Download the last official Raspbian Buster Lite from https://www.raspberrypi.org/downloads/raspbian/

Direct link: https://downloads.raspberrypi.org/raspbian_lite_latest

### 2 - Scrambling microSD card (patience here)

This is a good method to make the drive almost impossible to forensic extract previous data, apply this step if you're going to use a previously used microSD card (from a camera, from another raspberry Pi project, etc) so your previous data will be reasonably safe.
If you just buyed a new microSD card, this step is not really necessary.

```bash
# on OSX
sudo dd if=/dev/urandom of=/dev/YOUR_DEVICE_NAME bs=1m

# on linux
sudo dd if=/dev/urandom of=/dev/YOUR_DEVICE_NAME bs=1M
```

### 3 - Installing raspbian buster lite on microSD card

```bash
# on OSX
sudo dd if=raspbian-buster-lite.img of=/dev/YOUR_DEVICE_NAME bs=1m conv=sync

# on linux
sudo dd if=raspbian-buster-lite.img of=/dev/YOUR_DEVICE_NAME bs=1M conv=fdatasync
```

# Post-Install Config

### 1 - Launch raspi-config to expand filesystem and activate ssh server

```bash
sudo raspi-config
```

Remember to not change anything unnecessary (like localization options), less identifiable information, the better.

We first go to Network Options, and change the hostname, just to get rid of the default **raspberrypi** hostname (choose whatever name of your likes) and hide this piece of information from the network snoopers.

Then we go to Advanced Options and Expand Filesystem, in order to have the entire SD memory card storage at our disposal.

And finally we go to Interfacing Options and SSH, to enable remote command line access to our Pi using ssh protocol.

Now just reboot and access our device via ssh, with default raspbian credentials:

user **pi**, passwd **raspberry**

# Configuration

## Users

### 1 - Get rid of the default RPi credentials:

```bash
passwd
```

```bash
sudo passwd
```

## SSH


### 0 - Create a new SSH Key Pair for securing the server with a public key authentication

Usually we can connect to a remote server via SSH with a simple username/password, and that's ok in a lot of scenarios, but we are trying here to configure our **RPi Onion Router** in order to obtain better/reasonably security ( we don't want to risk someone hacking our router with some advanced exploit and monitor everything we are doing with the idea that we have complete anonymity ) so a good practice is to use an ssh user keypair in order to authenticate.
An ssh user keypair is an asymmetric cryptography mechanism, also know as public-key cryptography, similar to [PGP](https://es.wikipedia.org/wiki/Pretty_Good_Privacy), that use two keys, one private and one public; while the User Private Key must be kept secret (in your secure personal computer), the User Public key can be shared with anyone and with any server.

So, let's create a keypair and configure it to connect with our **RPi Onion Router**.

**In our secure personal computer** (IMPORTANT), create the keys (OSX or LINUX):

```bash
ssh-keygen -t rsa -b 8192 -C "sectorPi_rsa"
```

It will ask you where to save the keys and to set a password.

When done ( it can take a minute ) you will have a private key "myKey" and a public key "myKey.pub", in the .ssh directory of the localuser's home directory. Remember that the private key should not be shared with anyone who should not have access to your servers!

Now, copy our newly created PUBLIC key to the **RPi Onion Router**:

```bash
ssh-copy-id -i myKey.pub pi@RPI_ip_number
```

**Now back to our server**, just to check it, if we print the file ~/.ssh/authorized_keys:

```bash
cat ~/.ssh/authorized_keys
```

we will see our ssh-rsa public key added.

That's it, now we may SSH login to our server using the private key as authentication, so the time has come for configuring our SSH daemon for better security.

### 1 - Update ssh config, edit /etc/ssh/sshd_config:

```bash
sudo nano /etc/ssh/sshd_config
```
And edit:

```bash
# Disable ipv6
#ListenAddress ::
ListenAddress 0.0.0.0

# Disallow SSH access to root account
LoginGraceTime 60
PermitRootLogin no
StrictModes yes
MaxAuthTries 6
MaxSessions 3

# Don't read the user's ~/.rhosts and ~/.shosts files
IgnoreRhosts yes

# disable rhosts based authentication
RhostsAuthentication no
RhostsRSAAuthentication no

# enable RSA authentication
RSAAuthentication yes

# Disable X11Forwarding
X11Forwarding no

# disable challenge-response password
ChallengeResponseAuthentication no

# Disable tunneled cleartext password authentication and enable SSH public key only access
PasswordAuthentication no
PermitEmptyPasswords no
PubkeyAuthentication yes
AuthorizedKeysFile      .ssh/authorized_keys

# Add AllowUsers pi, in order to enable access for your default user ONLY
AllowUsers pi
```

Save it and restart ssh:

```bash
sudo /etc/init.d ssh restart
```

## APT sources


### 1 - Change apt sources

```bash
sudo nano /etc/apt/surces.list
```

And uncomment the deb-src line:

```bash
deb http://raspbian.raspberrypi.org/raspbian/ buster main contrib non-free rpi
deb-src http://raspbian.raspberrypi.org/raspbian/ buster main contrib non-free rpi
```

Save and launch an update:

```bash
sudo apt update && sudo apt dist-upgrade -y
```

## Encryption

Ok, this is a hard one, we are going to implement full disk encryption using LUKS, we'll just need patience, commitment and a USB flash drive, to solve this step.

First of all, why? Why go through all this work?

Well, a simple security problem with an RPi is that everyone with physical access can extract the SD card, copy it, manipulate it, open it as an external drive in a linux computer and do whatever with your system, so basically, that is a tremendous security flaw. If we encrypt our drive, we eliminate this flaw, or at least mitigate the flaw and make it almost impossible for a "non governmental or organized cyber-crime powered" entity ( or individual ) to spy on us.

**REMEMBER: LUKS encryption is not unbreakable, nothing is really, but with a proper strong password ( use a complex one if you're good with mnemonics, or use a password manager to remember it for you ), and due to the lack of hibernation/sleep state in our RPi ( there are advanced attack techniques that can extract data cached from RAM, and while in hibernation/sleep in a LUKS encrypted computer, our encryption master password is stored on RAM, so... ), we can say that this will reasonably secure our project some more.**

Hopefully we'll get through this without failure, but be aware, this step involves backing up your data to a USB drive and destroying all data on your SD card, and because of that we are doing it at the beginning, just in case, so we will not lose all our almost completed **RPi Onion Router**

Now, i'm going to use this tutorial from [robpol86.com](https://robpol86.com/raspberry_pi_luks.html) as reference, but there will be some differences as that tutorial was written for raspbian jessie, and we are on raspbian buster ( two releases later ).

Let's get to it!

### 1 - Install necessary software

```bash
sudo apt install busybox cryptsetup initramfs-tools expect
```

### 2 - Add a kernel post-install script

Raspbian doesn’t normally use an initrd/initramfs, so it doesn’t auto-update the one we’re about to create when a new kernel version comes out. Our initramfs holds kernel modules since they’re needed before the encrypted root file system can be mounted. When the kernel version changes it won’t be able to find its new modules.

Then we fix it writing a new file:

```bash
sudo nano /etc/kernel/postinst.d/initramfs-rebuild
```

And write this:

```bash
#!/bin/sh -e

# Rebuild initramfs.gz after kernel upgrade to include new kernel's modules.
# https://github.com/Robpol86/robpol86.com/blob/master/docs/_static/initramfs-rebuild.sh
# Save as (chmod +x): /etc/kernel/postinst.d/initramfs-rebuild

# Remove splash from cmdline.
if grep -q '\bsplash\b' /boot/cmdline.txt; then
  sed -i 's/ \?splash \?/ /' /boot/cmdline.txt
fi

# Exit if not building kernel for this Raspberry Pi's hardware version.
version="$1"
current_version="$(uname -r)"
case "${current_version}" in
  *-v7+)
    case "${version}" in
      *-v7+) ;;
      *) exit 0
    esac
  ;;
  *+)
    case "${version}" in
      *-v7+) exit 0 ;;
    esac
  ;;
esac

# Exit if rebuild cannot be performed or not needed.
[ -x /usr/sbin/mkinitramfs ] || exit 0
[ -f /boot/initramfs.gz ] || exit 0
lsinitramfs /boot/initramfs.gz |grep -q "/$version$" && exit 0  # Already in initramfs.

# Rebuild.
mkinitramfs -o /boot/initramfs.gz "$version"
```

Next we need to include **resize2fs** , **fdisk** and other kernel modules in our initramfs image, so we’ll need to create a hook file:

```bash
sudo nano /etc/initramfs-tools/hooks/resize2fs
```

And write this:

```bash
#!/bin/sh -e

# Copy resize2fs, fdisk, and other kernel modules into initramfs image.
# https://github.com/Robpol86/robpol86.com/blob/master/docs/_static/resize2fs.sh
# Save as (chmod +x): /etc/initramfs-tools/hooks/resize2fs

COMPATIBILITY=false  # Set to false to skip copying other kernel's modules.

PREREQ=""
prereqs () {
  echo "${PREREQ}"
}
case "${1}" in
  prereqs)
    prereqs
    exit 0
  ;;
esac

. /usr/share/initramfs-tools/hook-functions

copy_exec /sbin/resize2fs /sbin
copy_exec /sbin/fdisk /sbin
copy_exec /sbin/dumpe2fs /sbin
copy_exec /usr/bin/expect /sbin
cp -R /usr/share/tcltk/* ${DESTDIR}/lib/

# Raspberry Pi 1 and 2+3 use different kernels. Include the other.
if ${COMPATIBILITY}; then
  case "${version}" in
    *-v7+) other_version="$(echo ${version} |sed 's/-v7+$/+/')" ;;
    *+) other_version="$(echo ${version} |sed 's/+$/-v7+/')" ;;
    *)
      echo "Warning: kernel version doesn't end with +, ignoring."
      exit 0
  esac
  cp -r /lib/modules/${other_version} ${DESTDIR}/lib/modules/
fi
```

Ok, now let's build the new initramfs and make sure our utilities have been installed. The mkinitramfs command may print some WARNINGs from cryptsetup, but that should be fine since we’re using CRYPTSETUP=y. As long as cryptsetup itself is present in the initramfs it won’t be a problem.

```bash
sudo chmod +x /etc/kernel/postinst.d/initramfs-rebuild
sudo chmod +x /etc/initramfs-tools/hooks/resize2fs

echo 'CRYPTSETUP=y' | sudo tee --append /etc/cryptsetup-initramfs/conf-hook > /dev/null
sudo mkinitramfs -o /boot/initramfs.gz

# check it
lsinitramfs /boot/initramfs.gz | grep -P "sbin/(cryptsetup|resize2fs|fdisk|dumpe2fs|expect)"
#Make sure you see sbin/resize2fs, sbin/cryptsetup, sbin/dumpe2fs, sbin/expect, and sbin/fdisk in the output.
```

### 3 - Prepare the boot files

Let's check our partitions:

```bash
lsblk
```

My output:

```bash
NAME        MAJ:MIN RM  SIZE RO TYPE MOUNTPOINT
mmcblk0     179:0    0 59.5G  0 disk
├─mmcblk0p1 179:1    0  256M  0 part /boot
└─mmcblk0p2 179:2    0 59.2G  0 part /
```

So we have the /boot partition (mmcblk0p1) that need to remain unencrypted, and the / partition (mmcblk0p2) that we'll encrypt in a bit.

Now we need to prepare the boot files, telling the RPi to boot our soon-to-be-created encrypted partition. We’ll make these changes first since they’re relatively easily reversible if you mount your SD card on another computer, should you wish to abort this process:

```bash
# Append initramfs initramfs.gz followkernel to the end of /boot/config.txt
echo 'initramfs initramfs.gz followkernel' | sudo tee --append /boot/config.txt > /dev/null

# open /boot/cmdline.txt and search for root=YOUR_PARTITION_ID
# in my case i have root=PARTUUID=2f927c11-02

# Append cryptdevice=PARTUUID=2f927c11-02:sdcard to the end of /boot/cmdline.txt

# Now replace root=PARTUUID=2f927c11-02 with root=/dev/mapper/sdcard in /boot/cmdline.txt

# Then replace PARTUUID=2f927c11-02 with /dev/mapper/sdcard in /etc/fstab

# Append sdcard  PARTUUID=2f927c11-02  none    luks to the end of /etc/crypttab
echo 'sdcard PARTUUID=2f927c11-02 none luks' | sudo tee --append /etc/crypttab > /dev/null
```

Perfect, now reboot and let's hope we didn't commit any mistakes

```bash
sudo reboot
```

If everything was right, our RPi will fail to boot and automatically drop into the initramfs shell.

![Initramfs](https://github.com/d3cod3/SecTorPi/raw/master/img/intramfs.jpeg)

### 4 - Shrink and encrypt

Good, we are now in the initramfs shell, let's shrink our system partition and copy it to an external USB flash drive.
So, insert your USB drive and:

```bash
e2fsck -f /dev/mmcblk0p2  # Check SD card for errors for safety.
resize2fs -fM /dev/mmcblk0p2  # Shrink the file system on the SD card.
# Write down the number of 4k blocks long in the resize2fs output.
# ex. The file system on /dev/mmcblk0p2 is now 1397823 (4k) blocks long.
# Substitute "1397823" below with your number of interest.
dd bs=4k count=1397823 if=/dev/mmcblk0p2 | sha1sum # Write down the SHA1.
fdisk -l /dev/sda  # Make sure /dev/sda is your USB drive. If not check dmesg.
dd bs=4k count=1397823 if=/dev/mmcblk0p2 of=/dev/sda  # Copy data to USB drive.
dd bs=4k count=1397823 if=/dev/sda | sha1sum # Make sure it's the same value!
```

Now we wipe our system partition, create an empty encrypted one and copy back all our data.
The first **cryptsetup** command will prompt you for the password you want to use for your encrypted partition. Make sure it’s a strong one.

```bash
cryptsetup --cipher aes-cbc-essiv:sha256 luksFormat /dev/mmcblk0p2
cryptsetup luksOpen /dev/mmcblk0p2 sdcard  # Mounts the encrypted file system.
dd bs=4k count=1397823 if=/dev/sda of=/dev/mapper/sdcard # Copy back your data.
dd bs=4k count=1397823 if=/dev/mapper/sdcard | sha1sum # Make sure it's the same!
e2fsck -f /dev/mapper/sdcard  # Check encrypted SD card for errors.
resize2fs -f /dev/mapper/sdcard  # Expand back to full size.
```

Almost finished, remove USB drive and exit from initramfs shell

```bash
# Remove USB drive, no longer needed.
exit  # Continue to boot into your encrypted SD card.
```

### 5 - Build the new initramfs

Last step, rebuild our new initramfs:

```bash
sudo mkinitramfs -o /boot/initramfs.gz
sudo lsinitramfs /boot/initramfs.gz | grep -P "sbin/(cryptsetup|resize2fs|fdisk|dumpe2fs|expect)"
```

And that’s it. Reboot and it should prompt you with something like "Please unlock disk /dev/mmcblk0p2 (sdcard)", enter your chosen password and the system will boot. Now enter again from ssh, next chapter, networking!

## Net


### 0 - Before we start

In case we do not want to use the default RPi onboard wifi card, and instead use an external one, maybe one with a better antenna or whatever, we have the option to disable onboard wifi and bluetooth. And, as it can be considered common practice to disable what you're not going to use, if security is important for us, then we can do that just by editing the /boot/config.txt file:

```bash
sudo nano /boot/config.txt

# add this at the end
dtoverlay=disable-wifi
dtoverlay=disable-bt
```

So on startup, our RPi will recognize as **wlan0** our external wifi card, not the default onboard one.

### 1 - Install&configure necessary packages for make the rpi an access point in a standalone network

We'll configure here our wifi card **wlan0** as a router, assigning a static ip to the interface.

```bash
sudo apt install dnsmasq hostapd tcpdump
sudo nano /etc/dhcpcd.conf

interface wlan0   # Use the require wireless interface - usually wlan0
    static ip_address=192.168.66.1/24
    nohook wpa_supplicant

sudo systemctl restart dhcpcd
```

### 2 - Configure the DHCP server (dnsmasq)

Then we configure our dhcp server ip range, in order to have an automatic ip assigned to every connecting client. As we assigned to our wifi card/router the ip 192.168.66.1, we use a range starting from 192.168.66.2 till 192.168.66.200, but here you can trim it as you prefer, reducing the maximum number of clients or extending it. your choice.

```bash
sudo mv /etc/dnsmasq.conf /etc/dnsmasq.conf.orig
sudo nano /etc/dnsmasq.conf

interface=wlan0      # Use the require wireless interface - usually wlan0
dhcp-range=192.168.66.2,192.168.66.200,255.255.255.0,24h
# Set DHCP as authoritative
dhcp-authoritative

sudo systemctl reload dnsmasq
```

### 3 - Configure the access point host software (hostapd)

NOTE: wpa_key must be minimum 8 characters

Here we configure our access point, configuring his name (how will appear on wifi lists), the password and some more technical details. Remember to choose a good password, at least of 10 characters, in order to make it harder for brute force crackers.

```bash
sudo nano /etc/hostapd/hostapd.conf

interface=wlan0
driver=nl80211
ssid=YOUR_SSID_NAME
hw_mode=g
channel=5
wmm_enabled=0
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_passphrase=YOUR_SSID_PASSWORD
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
rsn_pairwise=CCMP
```

Now apply the config and restart the services:

```bash
sudo nano /etc/default/hostapd

DAEMON_CONF="/etc/hostapd/hostapd.conf"

sudo systemctl unmask hostapd
sudo systemctl enable hostapd
sudo systemctl start hostapd
```

### 4 - Install iptables-persistent and configure network address translation

```bash
sudo apt install iptables-persistent
```

And then run the following commands to create the network translation between the ethernet port eth0 and the wifi port wlan0:

```bash
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
sudo iptables -A FORWARD -i eth0 -o wlan0 -m state --state RELATED,ESTABLISHED -j ACCEPT
sudo iptables -A FORWARD -i wlan0 -o eth0 -j ACCEPT
```

Check it:

```bash
sudo iptables -t nat -S
sudo iptables -S
```

Then save it:

```bash
sudo sh -c "iptables-save > /etc/iptables/rules.v4"
```

Ok, right now we have a full working router, with a new wifi connection where we can connect from every computer or phone. Next steps, a little hardening and finally the installation of tor software.

### 5 - Hardening

Kernel hardening for security:

```bash
sudo nano /etc/sysctl.conf

# enable Spoof protection
net.ipv4.conf.default.rp_filter=1
net.ipv4.conf.all.rp_filter=1

# Enable TCP/IP SYN cookies
net.ipv4.tcp_syncookies=1

# enable packet forwarding for IPv4
net.ipv4.ip_forward=1

# Ignore ICMP broadcasts
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Ignore bogus ICMP errors
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Do not accept ICMP redirects (prevent MITM attacks)
net.ipv4.conf.all.accept_redirects = 0

# Do not send ICMP redirects
net.ipv4.conf.all.send_redirects = 0

# Do not accept IP source route packets
net.ipv4.conf.all.accept_source_route = 0

# rpi tweaks
vm.swappiness=1
vm.min_free_kbytes = 8192

```

## Tor

### 1 - Install tor, the onion routing software

```bash
sudo apt install tor
```

Now, configure it, just change the configured access point ip *192.168.66.1* if different:

```bash
sudo nano /etc/tor/torrc

Log notice file /var/log/tor/notices.log
VirtualAddrNetwork 10.192.0.0/10
AutomapHostsSuffixes .onion,.exit
AutomapHostsOnResolve 1
TransPort 192.168.66.1:9040
TransListenAddress 192.168.66.1
DNSPort 192.168.66.1:53
DNSListenAddress 192.168.66.1

# change exit ip every 10 seconds
CircuitBuildTimeout 10
LearnCircuitBuildTimeout 0
MaxCircuitDirtiness 10

# blacklist exit nodes by geolocation
# country codes list: https://b3rn3d.herokuapp.com/blog/2014/03/05/tor-country-codes/
StrictNodes 1
ExcludeExitNodes {CHOOSE_YOUR_COUNTRY_CODES_HERE}

```

Almost there, we now need to change out ip routing tables so that connections via the wifi interface (wlan0) will be routed through the tor software ONLY:

```bash
sudo iptables -F
sudo iptables -t nat -F
```

```bash
sudo iptables -t nat -A PREROUTING -i wlan0 -p udp --dport 53 -j REDIRECT --to-ports 53
sudo iptables -t nat -A PREROUTING -i wlan0 -p tcp --syn -j REDIRECT --to-ports 9040
```

```bash
sudo iptables -t nat -L
```

```bash
sudo sh -c "iptables-save > /etc/iptables/rules.v4"
```

Now we create our log file for debug:

```bash
sudo touch /var/log/tor/notices.log
sudo chown debian-tor /var/log/tor/notices.log
sudo chmod 644 /var/log/tor/notices.log
```
Then we activate the tor service in order to have it running automatically on startup and restart it to apply the new config:

```bash
sudo update-rc.d tor enable

sudo service tor restart

sudo service tor status
```

![Onion Router](https://github.com/d3cod3/SecTorPi/raw/master/img/raspberryPi3TorAccessPoint.png)

Ok, we have now our well configured **Onion Router**, and we can test it through several pages:

* https://check.torproject.org
* https://ipleak.org

### 2 - Install monit service to reload Tor service if down

This simple application automatically reload our Tor service if down, so we'll have the service always up.

```bash
sudo apt install monit

sudo nano /etc/monit/monitrc

check process gdm with pidfile /var/run/tor/tor.pid
   start program = "/etc/init.d/tor start"
   stop program = "/etc/init.d/tor stop"

sudo systemctl restart monit
sudo systemctl enable monit
```

## DNScrypt

If you want to add to our system DNS encryption, to prevent DNS spoofing we'll install dnscrypt, that using cryptographic signatures it verifies if the DNS response originates from the configured DNS resolver and haven’t been tampered with. This can prevent MITM (Man-in-the-Middle) attacks, or at least some of them.

Ok, we start with downloading DNSCrypt in our */opt* directory ( the last release is now 2.0.36, change the link below accordingly with the actual last release ):

```bash
cd /opt

sudo wget https://github.com/DNSCrypt/dnscrypt-proxy/releases/download/2.0.36/dnscrypt-proxy-linux_arm-2.0.36.tar.gz
```

Extract the prebuilt binary:

```bash
sudo tar -xf dnscrypt-proxy-linux_arm-2.0.36.tar.gz
```

And rename it

```bash
sudo mv linux-arm dnscrypt-proxy
```

Now, enter the directory and edit the config file:

```bash
cd dnscrypt-proxy

sudo cp example-dnscrypt-proxy.toml dnscrypt-proxy.toml

sudo nano dnscrypt-proxy.toml
```

Then edit it and save it:

```bash
# dnscrypt server list: https://dnscrypt.info/public-servers
server_names = ['cloudflare'] # choose here the one/s you prefer

# port 53 is already occupied by dnsmasq, so we need to use a different one
listen_addresses = ['127.0.2.1:54']

# Server must support DNS security extensions (DNSSEC)
require_dnssec = true
```

In order to have dnsmasq running with dnscrypt we need to modify our /etc/dnsmasq.conf:

```bash

sudo nano /etc/dnsmasq.conf

interface=wlan0      # Use the require wireless interface - usually wlan0
dhcp-range=192.168.66.2,192.168.66.200,255.255.255.0,24h
# Set DHCP as authoritative
dhcp-authoritative
# Redirect everything to dnscrypt-proxy
server=127.0.2.1#54
no-resolv
proxy-dnssec
```

Then restart dnsmasq:

```bash
sudo systemctl reload dnsmasq
```

Now we install and start the new service:

```bash
sudo ./dnscrypt-proxy -service install

sudo ./dnscrypt-proxy -service start

sudo ./dnscrypt-proxy -service status
```

Let's check it with netstat:

```bash
netstat -tulp
```

You will find in the output:

```bash
tcp        0      0 192.168.66.1:9040       0.0.0.0:*               LISTEN      966/tor             
tcp        0      0 0.0.0.0:domain          0.0.0.0:*               LISTEN      707/dnsmasq         
tcp        0      0 127.0.2.1:54            0.0.0.0:*               LISTEN      520/dnscrypt-proxy
```

So, if everything went ok, we will have dnsmasq redirecting all the port 53 requests to our dnscrypt proxy configured at 127.0.2.1 at port 54, so all DNS queries will be encrypted on the way.

That's it, finally we can check our DNS info from here:

* https://www.dnsleaktest.com

If everything were configured right, you'll see a lot of DNS servers with different location from your real one, and differents ISP from the one you're really using.

Enjoy!
