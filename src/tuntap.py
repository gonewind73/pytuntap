'''
Created on 2018年5月3日

@author: heguofeng
'''
import unittest
import struct

import subprocess
import sys
import socket
import time
from _thread import start_new_thread
import threading
import logging
import os
import math

if sys.platform.startswith("win"):
    import winreg as reg
    import win32file
    import pywintypes
    import win32event
else:
    import fcntl  # @UnresolvedImport

class Packet(object):
    def __init__(self,data=None,frame=None):
        if frame:
            self.load(frame)
            return
        if data:
            self.data = data

    def load(self,frame):
        self.data = frame[12+2:]

    def get_version(self):
        return self.data[0]>>4

    def get_src(self):
        return self.data[12:16]

    def get_dst(self):
        return self.data[12:16]


def TunTap(nic_type):
    if not sys.platform.startswith("win"):
        return Tap(nic_type)
    else:
        return WinTap(nic_type)

class Tap(object):
    def __init__(self,nic_type):
        self.nic_type = nic_type
        self.name = None
        self.handle = None
        self.ip = None
        self.mask = None
        self.gateway = None
        self.read_lock = threading.Lock()
        self.write_lock = threading.Lock()

    def create(self):
        TUNSETIFF = 0x400454ca
        TUNSETOWNER = 0x400454cc
        TUNSETGROUP = 0x400454ce
        TUNSETPERSIST = 0x400454cb
        IFF_TUN = 0x0001
        IFF_TAP = 0x0002
        IFF_MULTI_QUEUE = 0x0100
        IFF_NO_PI = 0x1000
        O_RDWR = 0x2
        # Open TUN device file.
        tun = os.open('/dev/net/tun', O_RDWR)
        if not tun:
            return None
        # Tall it we want a TUN device named tun0.
        if self.nic_type == "Tap":
            flags = IFF_TAP | IFF_NO_PI
        if self.nic_type == "Tun":
            flags = IFF_TUN | IFF_NO_PI
        ifr = struct.pack('16sH22s', b'\x00'*16, flags,b'\x00'*22)
        print(ifr)
        ret = fcntl.ioctl(tun, TUNSETIFF, ifr)
        print(ret,len(ret),ifr)
        logging.debug(ifr,ret)
        dev, _ = struct.unpack('16sH', ret[:18])
        dev = dev.decode().strip("\x00")
        self.name = dev
        print(dev)
        # Optionally, we want it be accessed by the normal user.
        fcntl.ioctl(tun, TUNSETOWNER, struct.pack("H",1000))
        fcntl.ioctl(tun, TUNSETGROUP, struct.pack("H",1000))
        fcntl.ioctl(tun, TUNSETPERSIST, struct.pack("B",True))
        self.handle = tun

        if self.handle:
            return self
        else:
            return None

    def get_maskbits(self,mask):
        masks = mask.split(".")
        maskbits = 0
        if len(masks)==4:
            for i in range(4):
                print(masks[i],256-int(masks[i]))
                nbit = math.log(256-int(masks[i]),2)
                if nbit == int(nbit):
                    maskbits += 8-nbit
                else:
                    return
        return int(maskbits)

    def config(self,ip,mask,gateway="0.0.0.0"):
        self.ip = ip
        self.mask = mask
        self.gateway = gateway
        nmask = self.get_maskbits(self.mask)
        print(self.name,nmask)
        try:
            subprocess.check_call('ip link set '+self.name+' up', shell=True)
            subprocess.check_call('ip addr add '+self.ip+'/%d '%nmask + " dev "+ self.name , shell=True)
        except:
            logging.warning("error when config")
            self.close()
#         subprocess.check_call('route add -net 192.168.0.0/24 gw 192.168.10.1 tun0',
#                               shell=True)
    def close(self):
        print(self.name)
        os.close(self.handle)
        try:
            mode_name = 'tun' if self.nic_type=="Tun" else 'tap'
            print('ip tuntap delete mode '+ mode_name + " "+ self.name)
#            subprocess.check_call('ip addr delete '+self.ip+'/%d '%self.get_maskbits(self.mask) + " dev "+ self.name , shell=True)
            subprocess.check_call('ip tuntap delete mode '+'tun ' if self.nic_type=="Tun" else 'tap ' + self.name , shell=True)

        except Exception as e:
            print(e)
            pass
        pass
    def read(self):
        self.read_lock.acquire()
        data = os.read(self.handle,1522)
        self.read_lock.release()
        return data
        pass
    def write(self,data):
        self.write_lock.acquire()
        # print(data)
        try:
            result = os.write(self.handle,data)
        except:
            pass
        self.write_lock.release()
        return result
        pass

class WinTap(Tap):
    def __init__(self,nic_type):
        super().__init__(nic_type)
        self.component_id = "tap0901"
        self.adapter_key = r'SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}'
        self.TAP_IOCTL_GET_MAC = self.TAP_CONTROL_CODE(1, 0)
        self.TAP_IOCTL_GET_VERSION  = self.TAP_CONTROL_CODE(2, 0)
        self.TAP_IOCTL_GET_MTU      = self.TAP_CONTROL_CODE(3, 0)
        self.TAP_IOCTL_GET_INFO     = self.TAP_CONTROL_CODE(4, 0)
        self.TAP_IOCTL_CONFIG_POINT_TO_POINT = self.TAP_CONTROL_CODE(5, 0)
        self.TAP_IOCTL_SET_MEDIA_STATUS = self.TAP_CONTROL_CODE(6, 0)
        self.TAP_IOCTL_CONFIG_DHCP_MASQ = self.TAP_CONTROL_CODE(7, 0)
        self.TAP_IOCTL_GET_LOG_LINE     = self.TAP_CONTROL_CODE(8, 0)
        self.TAP_IOCTL_CONFIG_DHCP_SET_OPT = self.TAP_CONTROL_CODE(9, 0)
        self.TAP_IOCTL_CONFIG_TUN = self.TAP_CONTROL_CODE(10, 0)

        self.read_overlapped = pywintypes.OVERLAPPED()
        eventhandle = win32event.CreateEvent(None,True,False,None)
        self.read_overlapped.hEvent= eventhandle
        self.write_overlapped = pywintypes.OVERLAPPED()
        eventhandle = win32event.CreateEvent(None,True,False,None)
        self.write_overlapped.hEvent= eventhandle
        self.buffer =  win32file.AllocateReadBuffer(2000)


    def get_device_guid(self):
        with reg.OpenKey(reg.HKEY_LOCAL_MACHINE, self.adapter_key) as adapters:
            try:
                for i in range(10000):
                    key_name = reg.EnumKey(adapters, i)
#                     print(key_name)
                    with reg.OpenKey(adapters, key_name) as adapter:
                        try:
                            component_id = reg.QueryValueEx(adapter, 'ComponentId')[0]
#                             print(component_id)
                            if component_id == self.component_id:
                                regid = reg.QueryValueEx(adapter, 'NetCfgInstanceId')[0]
                                return regid
                        except WindowsError as err:
                            pass
            except WindowsError as err:
                pass

    def CTL_CODE(self,device_type, function, method, access):
        return (device_type << 16) | (access << 14) | (function << 2) | method;

    def TAP_CONTROL_CODE(self,request, method):
#         print("%x"%self.CTL_CODE(34, request, method, 0))
        return self.CTL_CODE(34, request, method, 0)

    def getNameByMac(self,mac_string):
        print(mac_string)
        result = subprocess.check_output("ipconfig/all",shell=True).decode("gbk").encode().decode()

        res = result.split("适配器")

        for i in range(1,len(res)):
            if res[i].find(mac_string)>0:

                return res[i].split(":")[0].strip()

    def create(self):
        guid = self.get_device_guid()
#         print('guid: ', guid)
        self.handle = win32file.CreateFile("\\\\.\\Global\\%s.tap"%guid,
                                          win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                                          0,#win32file.FILE_SHARE_READ | win32file.FILE_SHARE_WRITE,
                                          None, win32file.OPEN_EXISTING,
                                          win32file.FILE_ATTRIBUTE_SYSTEM | win32file.FILE_FLAG_OVERLAPPED,None)

#         print(handle)

        if self.handle:
            return self
        else:
            return None

    def config(self,ip,mask,gateway="0.0.0.0"):
        self.ip = ip
        self.mask = mask
        self.gateway = gateway
        try:
            code = b'\x01\x00\x00\x00'
#             code[0]=b'\x01'
            result = win32file.DeviceIoControl(self.handle,self.TAP_IOCTL_SET_MEDIA_STATUS,code,512,None)
            print("status",result)

            ipnet = struct.pack("I",struct.unpack("I", socket.inet_aton(self.ip))[0]&struct.unpack("I", socket.inet_aton(self.mask))[0])
            ipcode = socket.inet_aton(self.ip)+ipnet+socket.inet_aton(self.mask)
            if self.nic_type=="Tap":
                flag = self.TAP_IOCTL_CONFIG_POINT_TO_POINT
            if self.nic_type=="Tun":
                flag =  self.TAP_IOCTL_CONFIG_TUN
            result = win32file.DeviceIoControl(self.handle, flag,ipcode, 16,None)
            print("config nic result",result)
#             result = win32file.DeviceIoControl(self.handle, self.TAP_IOCTL_CONFIG_TUN,
#                                               ipcode, 16,None)
#             print("config tun",result)
            mac= b'0'*6
            realmac = win32file.DeviceIoControl(self.handle,self.TAP_IOCTL_GET_MAC,mac,6,None)
            print(realmac)

            mac_string = ""
            for i in range(len(realmac)):
                mac_string += "%02X"%realmac[i]
                if i< len(realmac)-1:
                    mac_string +="-"

            self.name = self.getNameByMac(mac_string)
            print(self.name)
        except:
            win32file.CloseHandle(self.handle)

        sargs = r"netsh interface ip set address name=NAME source=static addr=ADDRESS mask=MASK gateway=GATEWAY"
#         args = sargs.split(" ")
#         args[5] = "name=\"%s\""%self.name
#         args[7] = "address=%s"%self.ip
#         args[8] = "mask=%s"%self.mask
#         args[9] = "gateway=%s"%self.gateway
        sargs = sargs.replace("NAME","\"%s\""%self.name)
        sargs = sargs.replace("ADDRESS",self.ip)
        sargs = sargs.replace("MASK",self.mask)
        if self.gateway == "0.0.0.0":
            sargs = sargs.replace("gateway=GATEWAY","")
        else:
            sargs = sargs.replace("GATEWAY",self.gateway)
        print(sargs)

#         args = 'netsh interface ip set address name=tap0 source=static addr=198.168.1.84 mask=255.255.255.0 gateway=192.168.1.1'
        subprocess.check_call(sargs,shell=True)

    def read(self):
        self.read_lock.acquire()
        result = None
        try:
            win32event.ResetEvent(self.read_overlapped.hEvent)
            err,data = win32file.ReadFile(self.handle,self.buffer,self.read_overlapped)
            if err == 997:#ERROR_IO_PENDING
                n = win32file.GetOverlappedResult(self.handle,self.read_overlapped,True)
                result = bytes(data[:n])
            else:
                result = bytes(data)
        finally:
            self.read_lock.release()
        return result


    def write(self,data):
        self.write_lock.acquire()
        writelen = 0
        try:
            win32event.ResetEvent(self.write_overlapped.hEvent)
            err,writelen = win32file.WriteFile(self.handle,data,self.write_overlapped)
            if err == 997:
                writelen = win32file.GetOverlappedResult(self.handle,self.write_overlapped,True)
        finally:
            self.write_lock.release()
        return writelen


    def close(self):
        win32file.CloseHandle(self.handle)


class Test(unittest.TestCase):


    def setUp(self):

        pass


    def tearDown(self):
        pass

    def readtest(self,tap):
        while True:
            p = tap.read()
            if not p:
                continue
            if tap.nic_type == "Tap":
                packet = Packet(frame=p)
            else:
                packet = p
            if not packet.get_version()==4:
                continue
            print(packet.data)



    def testTap(self):
        if sys.platform.startswith("win"):
            tap = WinTap("Tap")
        else:
            tap = Tap("Tap")
        tap.create()
        tap.config("192.168.2.82","255.255.255.0")
        start_new_thread(self.readtest,(tap,))
        s=input("press any key to quit!")
        tap.close()
        pass


    def testTun(self):
        if sys.platform.startswith("win"):
            tap = WinTap("Tun")
        else:
            tap = Tap("Tun")
        tap.create()
        tap.config("192.168.2.82","255.255.255.0")
        start_new_thread(self.readtest,(tap,))
        s=input("press any key to quit!")
        tap.close()
        pass

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
#     unittest.main()

    suite = unittest.TestSuite()
    if len(sys.argv) == 1:
        suite = unittest.TestLoader().loadTestsFromTestCase(Test)
    else:
        for test_name in sys.argv[1:]:
            print(test_name)
            suite.addTest(Test(test_name))

    unittest.TextTestRunner(verbosity=2).run(suite)
