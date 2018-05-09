 TUN/TAP package for Linux and Windows
================================

``pytuntap`` is a Python module for you create TUN/TAP device very easily.
It canbe work both on Linux and Windows

License: MIT (see LICENSE)

Installation and Dependencies
-----------------------------

Install ``pytuntap`` with ``pip install python-pytuntap``

As ``pytuntap`` is python wrapper for tuntap driver on Linux , and openvpn driver on
Windows. If you use it on windows, you should install openvpn's tap driver first.
please refer to openvpn ,how to install it .

Documentation
-------------

NOTE: On most distributions you will need to be root to create TUN/TAP devices.

To create a TUN device::

    from tuntap import TunTap

    tun = TunTap(nic_type="Tun",nic_name="tun0")

To create a TAP device::

    from tuntap import TunTap

    tap = TunTap(nic_type="Tap",nic_name="tap0")

To config device:

    tap.config(ip="192.168.1.10",mask="255.255.255.0",gateway="192.168.1.254")

You can get some parameters of the device directly::

    print(tun.name,tun.ip,tun.mask)

If the device is a TAP you can also get/set its MAC address::

    print(tap.mac)

To read/write to the device, use the methods ``read(size)`` and
``write(buf)``::

    buf = tun.read(size)
    tun.write(buf)

To close the device::

        tun.close()

you can also use ``TunTapDevice`` objects with all functions that expect a
``tun.handle`` method (e.g ``select()``)
