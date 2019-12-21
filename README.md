# SecTorPi

## A Reasonably Secure Raspberry Pi 3 Tor Access Point

![Onion Router](https://github.com/d3cod3/SecTorPi/raw/master/img/onion-router.jpg)


Table of Contents
=================

  * [Description](#description)
  * [Install](#install)
  * [Post-Install Config](#post-install-config)
  * [Configuration](#configuration)
    * [Users](#users)
      * [SSH](#ssh)


# Description

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

# Configuration


## Users

## SSH
