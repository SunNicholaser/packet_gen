import time

try:
    import scapy.all as scapy
except:
    import scapy as scapy

MINSIZE = 0
def simple_tcp_packet(pktlen=400, 
                      dl_dst='48:d2:24:0f:60:52',
                      dl_src='00:1b:21:02:d1:57',
                      dl_vlan_enable=False,
                      dl_vlan=0,
                      dl_vlan_pcp=0,
                      dl_vlan_cfi=0,
                      ip_src='1.1.1.5',
                      ip_dst='1.1.1.125',
                      ip_tos=0,
                      tcp_sport=1234,
                      tcp_dport=80,
                      ip_ihl=None,
                      ip_options=False
                      ):
    """
    Return a simple dataplane TCP packet

    Supports a few parameters:
    @param len Length of packet in bytes w/o CRC
    @param dl_dst Destinatino MAC
    @param dl_src Source MAC
    @param dl_vlan_enable True if the packet is with vlan, False otherwise
    @param dl_vlan VLAN ID
    @param dl_vlan_pcp VLAN priority
    @param ip_src IP source
    @param ip_dst IP destination
    @param ip_tos IP ToS
    @param tcp_dport TCP destination port
    @param ip_sport TCP source port

    Generates a simple TCP request.  Users
    shouldn't assume anything about this packet other than that
    it is a valid ethernet/IP/TCP frame.
    """

    if MINSIZE > pktlen:
        pktlen = MINSIZE

    # Note Dot1Q.id is really CFI
    if (dl_vlan_enable):
        pkt = scapy.Ether(dst=dl_dst, src=dl_src)/ \
            scapy.Dot1Q(prio=dl_vlan_pcp, id=dl_vlan_cfi, vlan=dl_vlan)/ \
            scapy.IP(src=ip_src, dst=ip_dst, tos=ip_tos, ihl=ip_ihl)/ \
            scapy.TCP(sport=tcp_sport, dport=tcp_dport)
    else:
        if not ip_options:
            pkt = scapy.Ether(dst=dl_dst, src=dl_src)/ \
                scapy.IP(src=ip_src, dst=ip_dst, tos=ip_tos, ihl=ip_ihl)/ \
                scapy.TCP(sport=tcp_sport, dport=tcp_dport)
        else:
            pkt = scapy.Ether(dst=dl_dst, src=dl_src)/ \
                scapy.IP(src=ip_src, dst=ip_dst, tos=ip_tos, ihl=ip_ihl, options=ip_options)/ \
                scapy.TCP(sport=tcp_sport, dport=tcp_dport)

    pkt = pkt/("D" * (pktlen - len(pkt)))
    
    #print pkt.show()
    #print scapy.Ether(str(pkt)).show()

    return pkt


def simple_udp_packet(pktlen=100,
                      dl_dst='48:d2:24:0f:60:52',
                      dl_src='00:1b:21:02:d1:57',
                      dl_vlan_enable=False,
                      dl_vlan=0,
                      dl_vlan_pcp=0,
                      dl_vlan_cfi=0,
                      ip_src='1.1.1.5',
                      ip_dst='1.1.1.125',
                      ip_tos=0,
                      udp_sport=4567,
                      udp_dport=9,
                      ip_ihl=None,
                      ip_options=False
                      ):
    """
    Return a simple dataplane UDP packet

    Supports a few parameters:
    @param len Length of packet in bytes w/o CRC
    @param dl_dst Destinatino MAC
    @param dl_src Source MAC
    @param dl_vlan_enable True if the packet is with vlan, False otherwise
    @param dl_vlan VLAN ID
    @param dl_vlan_pcp VLAN priority
    @param ip_src IP source
    @param ip_dst IP destination
    @param ip_tos IP ToS
    @param udp_dport UDP destination port
    @param udp_sport UDP source port

    Generates a simple UDP packet.  Users
    shouldn't assume anything about this packet other than that
    it is a valid ethernet/IP/UDP frame.
    """
    if 0 > pktlen:
        pktlen = MINSIZE

    # create udp header
    udp = scapy.UDP(sport=udp_sport, dport=udp_dport)

    # create ip header 
    if not ip_options:
        ip = scapy.IP(src=ip_src, dst= ip_dst, tos=ip_tos, ihl=ip_ihl)
    else:
        ip = scapy.IP(src=ip_src, dst=ip_dst, tos=ip_tos, ihl=ip_ihl, options=ip_options)

    # create ethernet header
    ether = scapy.Ether(dst=dl_dst, src=dl_src)

    # add the vlan header if if is enabled and create the pkt.
    if dl_vlan_enable :
        dot1q = scapy.Dot1Q(prio=dl_vlan_pcp, id=dl_vlan_cfi, vlan=dl_vlan)
        pkt = ether/ dot1q / ip / udp
    else:
        pkt = ether/ ip / udp

    pkt = pkt/("D" * (pktlen - len(pkt)))

    #print pkt.show()
    return pkt




def simple_eth_packet(pktlen=60,
                      dl_src='00:01:02:03:04:05',
                      dl_dst='01:80:c2:00:00:0e',
                      dl_type=0x88cc):

    if MINSIZE > pktlen:
        pktlen = MINSIZE
    pkt = scapy.Ether(dst=dl_dst, src=dl_src, type=dl_type)

    pkt = pkt/("0" * (pktlen - len(pkt)))

    return pkt


if __name__ == "__main__":
	import time
	from optparse import OptionParser

	parser = OptionParser()
	parser.add_option('-n','--npacket', dest = 'num_pack',type=int, help = 'number of packet')
	parser.add_option('-i', '--invalid', action="store_true",dest = 'invalid_pkt', default=False, help = 'invalid pkt')
	(options, args) = parser.parse_args()
	print type(options)
	num_pack = options.num_pack
	invalid_pkt = options.invalid_pkt

	for i in range(0,num_pack):
		#packet = simple_eth_packet()
		packet = simple_tcp_packet(pktlen=100)
    		#packet = simple_udp_packet()
		scapy.sendp(packet, iface = "eth1",count=1)
		#time.sleep(10)
		
		if invalid_pkt:
			invalid_packet = simple_tcp_packet(ip_src='1.1.1.6', ip_dst='1.1.1.123', pktlen=100)
			print 'sending invalid packet'
			scapy.sendp(invalid_packet, iface='eth1')


