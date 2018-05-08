import sys
from tuntap import Packet,TunTap
import optparse
from _thread import start_new_thread
import traceback

def readtest(tap):
    while not tap.quitting:
        p = tap.read()
        if not p:
            continue
        if tap.nic_type == "Tap":
            packet = Packet(frame=p)
        else:
            packet = Packet(data=p)
        if not packet.get_version()==4:
            continue
        print(''.join('{:02x} '.format(x) for x in packet.data))
        if tap.nic_type == "Tun":
            pingback = p[:12]+p[16:20]+p[12:16]+p[20:]
            tap.write(pingback)

def main():
    parser = optparse.OptionParser()
    parser.add_option('--nic_type', default='Tun',dest='nic_type',
            help='set type Tun or Tap')
    parser.add_option('--nic_name', default='',dest='nic_name',
            help='set device name')
    parser.add_option('--tap-addr', default='192.168.33.10',dest='taddr',
            help='set tunnel local address')
    parser.add_option('--tap-netmask', default='255.255.255.0',dest='tmask',
            help='set tunnel netmask')
    parser.add_option('--tap-mtu', type='int', default=1500,dest='tmtu',
            help='set tunnel MTU')
    parser.add_option('--local-addr', default='0.0.0.0', dest='laddr',
            help='set local address [%default]')
    parser.add_option('--local-port', type='int', default=12000, dest='lport',
            help='set local port [%default]')
    # parser.add_option('--remote-addr', dest='raddr',
    #         help='set remote address')
    # parser.add_option('--remote-port', type='int', dest='rport',
    #         help='set remote port')
    opt, args = parser.parse_args()
    # if not (opt.taddr and opt.raddr and opt.rport):
    #     parser.print_help()
    #     return 1
    try:
        tuntap = TunTap(opt.nic_type)
        tuntap.create()
        tuntap.config(opt.taddr, opt.tmask)
        #, opt.tmtu, opt.laddr,opt.lport, opt.raddr, opt.rport)
    except Exception as e:
        print(str(e),traceback.format_exc())
        traceback.print_stack(limit=10)
        return 1
    start_new_thread(readtest,(tuntap,))
    input("press return key to quit!")
    tuntap.close()
    return 0

if __name__ == '__main__':
    sys.exit(main())
