import numpy as np
from scapy.utils import hexdump

# d1={1,2,3,45}
# Things to Add
# IP length
# TCP length
# MQTT


def Sport(packet):

    if packet.haslayer("TCP"):
        srcproto = packet["TCP"].sport
    elif packet.haslayer("UDP"):
        srcproto = packet["UDP"].sport
    elif packet.haslayer("ARP"):
        srcproto = "ARP"
    elif packet.haslayer("ICMP"):
        srcproto = "ICMP"
    else:
        srcproto = ""
    return srcproto


def Dport(packet):
    if packet.haslayer("TCP"):
        dstproto = packet["TCP"].dport
    elif packet.haslayer("UDP"):
        dstproto = packet["UDP"].dport
    elif packet.haslayer("ARP"):
        dstproto = "ARP"
    elif packet.haslayer("ICMP"):
        dstproto = "ICMP"
    else:
        dstproto = ""
    # print(dstproto)
    return dstproto


def iptype(packet):
    if packet.haslayer("IP") | packet.haslayer("ARP") | packet.haslayer("ICMP"):  # IPv4
        ty = 0
    elif packet.haslayer("IPv6"):  # ipv6
        ty = 1
    else:
        ty = np.NaN
    return ty


def IPsrc(packet):
    if packet.haslayer("IP"):  # IPv4
        srcIP = packet["IP"].src
    elif packet.haslayer("IPv6"):  # ipv6
        srcIP = packet["IPv6"].src
    elif packet.haslayer("ARP"):  # is ARP
        srcIP = packet["ARP"].psrc  # src IP (ARP)
    else:
        srcIP = packet.src
    return srcIP


def IPdst(packet):
    if packet.haslayer("IP"):  # IPv4
        dstIP = packet["IP"].dst
    elif packet.haslayer("IPv6"):  # ipv6
        dstIP = packet["IPv6"].dst
    elif packet.haslayer("ARP"):  # is ARP
        dstIP = packet["ARP"].pdst  # src IP (ARP)
    else:
        dstIP = packet.dst
    return dstIP


def subnet(
    packet,
):  # cpp: this is all given to you in the direction string of the instance (NO NEED FOR THIS FUNCTION)
    IPtype = iptype(packet)
    srcIP = IPsrc(packet)
    dstIP = IPdst(packet)
    if packet.haslayer("Ether"):
        eth_src = packet["Ether"].src
        eth_dst = packet["Ether"].dst
    if IPtype == 0:  # is IPv4
        lstP = srcIP.rfind(".")
        src_subnet = srcIP[0:lstP:]
        lstP = dstIP.rfind(".")
        dst_subnet = dstIP[0:lstP:]
    elif IPtype == 1:  # is IPv6
        src_subnet = srcIP[0 : round(len(srcIP) / 2) :]
        dst_subnet = dstIP[0 : round(len(dstIP) / 2) :]
    else:  # no Network layer, use MACs
        src_subnet = eth_src
        dst_subnet = eth_dst

    return str(src_subnet), str(dst_subnet)


def protocol(packet):

    if packet.haslayer("TCP"):
        pro = "TCP"
    elif packet.haslayer("UDP"):
        pro = "UDP"
    elif packet.haslayer("ARP"):
        pro = "ARP"
    elif packet.haslayer("ICMP"):
        pro = "ICMP"
    else:
        pro = "other"
    return pro


# function to return binary array of the packet
def rawbin(packet):
    array = []
    for c in bytes(packet):
        temp = bin(int(c))[2:].zfill(8)
        # print(temp)
        for t in temp:
            array.append(int(t))
    # print(hexdump(packet))
    # print(array)
    # print("hello")
    return array


# MQTT header information to add
# HTTPS


mapper = {
    "packet": "all",
    "ARP":'ppy.layer12.arp.ARP',
    "IP": "ppy.layer3.ip.IP",
    "TCP": "ppy.layer4.tcp.TCP",
    "UDP": "ppy.layer4.udp.UDP",
    "ETHERNET": "ppy.layer12.ethernet.Ethernet",
    "IEEE":'ppy.layer12.ieee80211.IEEE80211',
    "MQTT":'ppy.layer567.mqtt.MQTTBase',
    "HTTP":'ppy.layer567.http.HTTP',
    "DNS":'ppy.layer567.dns.DNS',

    
    # "HTTP":"ppy.layer567.http.HTTP",
    # "DNS":"ppy.layer567.dns.DNS",
    # "DHCP":'ppy.layers567.dhcp.DHCP',
    # "MQTT":"ppy.layers567.mqtt.Publish",          #  Connect Publish MQTTBase PubAck PubRec Disconnect
    # "ICMP":"ppy.layer3.icmp.ICMP",
    # "NTP":'ppy.layer567.ntp.NTP'
    
}
# mapper={
#     'all':{'layers':'layers'},
#   'ip.IP':{'IP dst':'dst_s','IP src':'src_s','IP proto':'p'},
#     'tcp.TCP':{'TCP sport':'sport','TCP dport':'dport'},
#     'udp.UDP':{'UDP sport':'sport','UDP dport':'dport'}
# }


# mapper={
#     'packet layers': '[i for i in packet.layers]',
#     'packet time': 'ts',
#     'packet len': 'len(pkt1)',
#     'IP dst': 'pkt1[ip.IP].dst_s',
#     'IP flags': 'packet.ip.flags',
#     "IP src": 'pkt1[ip.IP].src_s',
#     "IP proto":'pkt1[ip.IP].p',
#     "TCP sport":'pkt1[tcp.TCP].sport',
#     "TCP dport":'pkt1[tcp.TCP].dport',
#     "UDP sport":'pkt1[udp.UDP].sport',
#     "UDP dport":'pkt1[udp.UDP].dport',
# }


# mapper={
#  "packet bytes":"",
#  'direction':' "".join(subnet(packet)) ',
#  'src subnet':'subnet(packet)[0]',
#  'dst subnet':'subnet(packet)[1]',
#  'protocol':'protocol(packet)',
#  'sport':'Sport(packet)',
#  'dport':'Dport(packet)',
#  'IP type':'iptype(packet)',
#  'ARP hwdst': 'pacet[ARP].hwdst',
#  'ARP hwlen': 'packet[ARP].hwlen',
#  'ARP hwsrc': 'packet[ARP].hwsrc',
#  'ARP hwtype': 'packet[ARP].hwtype',
#  'ARP op': 'packet[ARP].op',
#  'ARP pdst': 'packet[ARP].pdst',
#  'ARP plen': 'packet[ARP].plen',
#  'ARP psrc': 'packet[ARP].psrc',
#  'ARP ptype': 'packet[ARP].ptype',
#  'CookedLinux lladdrlen': 'packet[CookedLinux].lladdrlen',
#  'CookedLinux lladdrtype': 'packet[CookedLinux].lladdrtype',
#  'CookedLinux pkttype': 'packet[CookedLinux].pkttype',
#  'CookedLinux proto': 'packet[CookedLinux].proto',
#  'CookedLinux src': 'packet[CookedLinux].src',
#  'DNS aa': 'packet[DNS].aa',
#  'DNS ad': 'packet[DNS].ad',
#  'DNS an': 'packet[DNS].an',
#  'DNS ancount': 'packet[DNS].ancount',
#  'DNS ar': 'packet[DNS].ar',
#  'DNS arcount': 'packet[DNS].arcount',
#  'DNS cd': 'packet[DNS].cd',
#  'DNS id': 'packet[DNS].id',
#  'DNS length': 'packet[DNS].length',
#  'DNS ns': 'packet[DNS].ns',
#  'DNS nscount': 'packet[DNS].nscount',
#  'DNS opcode': 'packet[DNS].opcode',
#  'DNS query': 'packet[DNS].qd',
#  'DNS qdcount': 'packet[DNS].qdcount',
#  'DNS qr': 'packet[DNS].qr',
#  'DNS ra': 'packet[DNS].ra',
#  'DNS rcode': 'packet[DNS].rcode',
#  'DNS rd': 'packet[DNS].rd',
#  'DNS tc': 'packet[DNS].tc',
#  'DNS z': 'packet[DNS].z',
#  'Ether dst': 'packet[Ether].dst',
#  'Ether src': 'packet[Ether].src',
#  'Ether type': 'packet[Ether].type',
#  'ICMP chksum': 'packet[ICMP].chksum',
#  'ICMP code': 'packet[ICMP].code',
#  'ICMP length': 'packet[ICMP].length',
#  'ICMP nexthopmtu': 'packet[ICMP].nexthopmtu',
#  'ICMP reserved': 'packet[ICMP].reserved',
#  'ICMP type': 'packet[ICMP].type',
#  'ICMP unused': 'packet[ICMP].unused',
#  'IP chksum': 'packet[IP].chksum',
#  'IP dst': 'packet[IP].dst',
#  'IP flags': 'packet[IP].flags',
#  'IP frag': 'packet[IP].frag',
#  'IP id': 'packet[IP].id',
#  'IP ihl': 'packet[IP].ihl',
#  'IP len': 'packet[IP].len',
#  'IP options': 'packet[IP].IP.options',
#  'IP proto': 'packet[IP].proto',
#  'IP src': 'packet[IP].src',
#  'IP tos': 'packet[IP].tos',
#  'IP ttl': 'packet[IP].ttl',
#  'IP version': 'packet[IP].version',
#  'IPerror chksum': 'packet[IPerror].chksum',
#  'IPerror dst': 'packet[IPerror].dst',
#  'IPerror flags': 'packet[IPerror].flags',
#  'IPerror frag': 'packet[IPerror].frag',
#  'IPerror id': 'packet[IPerror].id',
#  'IPerror ihl': 'packet[IPerror].ihl',
#  'IPerror len': 'packet[IPerror].len',
#  'IPerror proto': 'packet[IPerror].proto',
#  'IPerror src': 'packet[IPerror].src',
#  'IPerror tos': 'packet[IPerror].tos',
#  'IPerror ttl': 'packet[IPerror].ttl',
#  'IPerror version': 'packet[IPerror].version',
#  'LLMNRQuery an': 'packet[LLMNRQuery].an',
#  'LLMNRQuery ancount': 'packet[LLMNRQuery].ancount',
#  'LLMNRQuery ar': 'packet[LLMNRQuery].ar',
#  'LLMNRQuery arcount': 'packet[LLMNRQuery].arcount',
#  'LLMNRQuery c': 'packet[LLMNRQuery].c',
#  'LLMNRQuery id': 'packet[LLMNRQuery].id',
#  'LLMNRQuery ns': 'packet[LLMNRQuery].ns',
#  'LLMNRQuery nscount': 'packet[LLMNRQuery].nscount',
#  'LLMNRQuery opcode': 'packet[LLMNRQuery].opcode',
#  'LLMNRQuery qd': 'packet[LLMNRQuery].qd',
#  'LLMNRQuery qdcount': 'packet[LLMNRQuery].qdcount',
#  'LLMNRQuery qr': 'packet[LLMNRQuery].qr',
#  'LLMNRQuery rcode': 'packet[LLMNRQuery].rcode',
#  'LLMNRQuery tc': 'packet[LLMNRQuery].tc',
#  'LLMNRQuery z': 'packet[LLMNRQuery].z',
#  'MAC_dst MAC_dst': 'packet[MAC_dst].MAC_dst',
#  'MAC_src MAC_src': 'packet[MAC_src].MAC_src',
#  'NBNSQueryRequest ANCOUNT': 'packet[NBNSQueryRequest].ANCOUNT',
#  'NBNSQueryRequest ARCOUNT': 'packet[NBNSQueryRequest].ARCOUNT',
#  'NBNSQueryRequest FLAGS': 'packet[NBNSQueryRequest].FLAGS',
#  'NBNSQueryRequest NAME_TRN_ID': 'packet[NBNSQueryRequest].NAME_TRN_ID',
#  'NBNSQueryRequest NSCOUNT': 'packet[NBNSQueryRequest].NSCOUNT',
#  'NBNSQueryRequest NULL': 'packet[NBNSQueryRequest].NULL',
#  'NBNSQueryRequest QDCOUNT': 'packet[NBNSQueryRequest].QDCOUNT',
#  'NBNSQueryRequest QUESTION_CLASS': 'packet[NBNSQueryRequest].QUESTION_CLASS',
#  'NBNSQueryRequest QUESTION_NAME': 'packet[NBNSQueryRequest].QUESTION_NAME',
#  'NBNSQueryRequest QUESTION_TYPE': 'packet[NBNSQueryRequest].QUESTION_TYPE',
#  'NBNSQueryRequest SUFFIX': 'packet[NBNSQueryRequest].SUFFIX',
#  'NBTDatagram DestinationName': 'packet[NBTDatagram].DestinationName',
#  'NBTDatagram Flags': 'packet[NBTDatagram].Flags',
#  'NBTDatagram ID': 'packet[NBTDatagram].ID',
#  'NBTDatagram Length': 'packet[NBTDatagram].Length',
#  'NBTDatagram NULL1': 'packet[NBTDatagram].NULL1',
#  'NBTDatagram NULL2': 'packet[NBTDatagram].NULL2',
#  'NBTDatagram Offset': 'packet[NBTDatagram].Offset',
#  'NBTDatagram SUFFIX1': 'packet[NBTDatagram].SUFFIX1',
#  'NBTDatagram SUFFIX2': 'packet[NBTDatagram].SUFFIX2',
#  'NBTDatagram SourceIP': 'packet[NBTDatagram].SourceIP',
#  'NBTDatagram SourceName': 'packet[NBTDatagram].SourceName',
#  'NBTDatagram SourcePort': 'packet[NBTDatagram].SourcePort',
#  'NBTDatagram Type': 'packet[NBTDatagram].Type',
#  'NBTSession LENGTH': 'packet[NBTSession].LENGTH',
#  'NBTSession RESERVED': 'packet[NBTSession].RESERVED',
#  'NBTSession TYPE': 'packet[NBTSession].TYPE',
#  'NTPHeader delay': 'packet[NTPHeader].delay',
#  'NTPHeader dispersion': 'packet[NTPHeader].dispersion',
#  'NTPHeader id': 'packet[NTPHeader].id',
#  'NTPHeader leap': 'packet[NTPHeader].leap',
#  'NTPHeader mode': 'packet[NTPHeader].mode',
#  'NTPHeader orig': 'packet[NTPHeader].orig',
#  'NTPHeader poll': 'packet[NTPHeader].poll',
#  'NTPHeader precision': 'packet[NTPHeader].precision',
#  'NTPHeader recv': 'packet[NTPHeader].recv',
#  'NTPHeader ref': 'packet[NTPHeader].ref',
#  'NTPHeader ref_id': 'packet[NTPHeader].ref_id',
#  'NTPHeader sent': 'packet[NTPHeader].sent',
#  'NTPHeader stratum': 'packet[NTPHeader].stratum',
#  'NTPHeader version': 'packet[NTPHeader].version',
#  'Padding load': 'packet[Padding].load',
#  'raw':'rawbin(packet)',
#  'SMB2_Header ChainOffset': 'packet[SMB2_Header].ChainOffset',
#  'SMB2_Header ChannelSequence': 'packet[SMB2_Header].ChannelSequence',
#  'SMB2_Header Command': 'packet[SMB2_Header].Command',
#  'SMB2_Header CreditCharge': 'packet[SMB2_Header].CreditCharge',
#  'SMB2_Header CreditsRequested': 'packet[SMB2_Header].CreditsRequested',
#  'SMB2_Header Flags': 'packet[SMB2_Header].Flags',
#  'SMB2_Header HeaderLength': 'packet[SMB2_Header].HeaderLength',
#  'SMB2_Header MessageID': 'packet[SMB2_Header].MessageID',
#  'SMB2_Header ProcessID': 'packet[SMB2_Header].ProcessID',
#  'SMB2_Header SessionID': 'packet[SMB2_Header].SessionID',
#  'SMB2_Header Signature': 'packet[SMB2_Header].Signature',
#  'SMB2_Header Start': 'packet[SMB2_Header].Start',
#  'SMB2_Header TreeID': 'packet[SMB2_Header].TreeID',
#  'SMB2_Header Unused': 'packet[SMB2_Header].Unused',
#  'SMB2_Negociate_Protocol_Request_Header Capabilities': 'packet[SMB2_Negociate_Protocol_Request_Header].Capabilities',
#  'SMB2_Negociate_Protocol_Request_Header ClientGUID': 'packet[SMB2_Negociate_Protocol_Request_Header].ClientGUID',
#  'SMB2_Negociate_Protocol_Request_Header DialectCount': 'packet[SMB2_Negociate_Protocol_Request_Header].DialectCount',
#  'SMB2_Negociate_Protocol_Request_Header NegociateContextOffset': 'packet[SMB2_Negociate_Protocol_Request_Header].NegociateContextOffset',
#  'SMB2_Negociate_Protocol_Request_Header NegociateCount': 'packet[SMB2_Negociate_Protocol_Request_Header].NegociateCount',
#  'SMB2_Negociate_Protocol_Request_Header Reserved': 'packet[SMB2_Negociate_Protocol_Request_Header].Reserved',
#  'SMB2_Negociate_Protocol_Request_Header Reserved2': 'packet[SMB2_Negociate_Protocol_Request_Header].Reserved2',
#  'SMB2_Negociate_Protocol_Request_Header SecurityMode': 'packet[SMB2_Negociate_Protocol_Request_Header].SecurityMode',
#  'SMB2_Negociate_Protocol_Request_Header StructureSize': 'packet[SMB2_Negociate_Protocol_Request_Header].StructureSize',
#  'SMBNegociate_Protocol_Request_Header ByteCount': 'packet[SMBNegociate_Protocol_Request_Header].ByteCount',
#  'SMBNegociate_Protocol_Request_Header Command': 'packet[SMBNegociate_Protocol_Request_Header].Command',
#  'SMBNegociate_Protocol_Request_Header Error_Class': 'packet[SMBNegociate_Protocol_Request_Header].Error_Class',
#  'SMBNegociate_Protocol_Request_Header Error_code': 'packet[SMBNegociate_Protocol_Request_Header].Error_code',
#  'SMBNegociate_Protocol_Request_Header Flags': 'packet[SMBNegociate_Protocol_Request_Header].Flags',
#  'SMBNegociate_Protocol_Request_Header Flags2': 'packet[SMBNegociate_Protocol_Request_Header].Flags2',
#  'SMBNegociate_Protocol_Request_Header MID': 'packet[SMBNegociate_Protocol_Request_Header].MID',
#  'SMBNegociate_Protocol_Request_Header PID': 'packet[SMBNegociate_Protocol_Request_Header].PID',
#  'SMBNegociate_Protocol_Request_Header PIDHigh': 'packet[SMBNegociate_Protocol_Request_Header].PIDHigh',
#  'SMBNegociate_Protocol_Request_Header Reserved': 'packet[SMBNegociate_Protocol_Request_Header].Reserved',
#  'SMBNegociate_Protocol_Request_Header Signature': 'packet[SMBNegociate_Protocol_Request_Header].Signature',
#  'SMBNegociate_Protocol_Request_Header Start': 'packet[SMBNegociate_Protocol_Request_Header].Start',
#  'SMBNegociate_Protocol_Request_Header TID': 'packet[SMBNegociate_Protocol_Request_Header].TID',
#  'SMBNegociate_Protocol_Request_Header UID': 'packet[SMBNegociate_Protocol_Request_Header].UID',
#  'SMBNegociate_Protocol_Request_Header Unused': 'packet[SMBNegociate_Protocol_Request_Header].Unused',
#  'SMBNegociate_Protocol_Request_Header WordCount': 'packet[SMBNegociate_Protocol_Request_Header].WordCount',
#  'SMBNegociate_Protocol_Request_Header_Generic Start': 'packet[SMBNegociate_Protocol_Request_Header_Generic].Start',
#  'SMBNegociate_Protocol_Request_Tail BufferData': 'packet[SMBNegociate_Protocol_Request_Tail].BufferData',
#  'SMBNegociate_Protocol_Request_Tail BufferFormat': 'packet[SMBNegociate_Protocol_Request_Tail].BufferFormat',
#  'TCP EOL': 'packet[TCP].options.EOL',
#  'TCP MSS': 'packet[TCP].options.MSS',
#  'TCP NOP': 'packet[TCP].options.NOP',
#  'TCP SAck': 'packet[TCP].options.SAck',
#  'TCP SAckOK': 'packet[TCP].options.SAckOK',
#  'TCP Timestamp': 'packet[TCP].options.Timestamp',
#  'TCP WScale': 'packet[TCP].options.WScale',
#  'TCP ack': 'packet[TCP].ack',
#  'TCP chksum': 'packet[TCP].chksum',
#  'TCP dataofs': 'packet[TCP].dataofs',
#  'TCP dport': 'packet[TCP].dport',
#  'TCP flags': 'packet[TCP].flags',
#  'TCP reserved': 'packet[TCP].reserved',
#  'TCP seq': 'packet[TCP].seq',
#  'TCP sport': 'packet[TCP].sport',
#  'TCP urgptr': 'packet[TCP].urgptr',
#  'TCP window': 'packet[TCP].window',
#  'UDP chksum': 'packet[UDP].chksum',
#  'UDP dport': 'packet[UDP].dport',
#  'UDP len': 'packet[UDP].len',
#  'UDP sport': 'packet[UDP].sport',
#  'UDPerror chksum': 'packet[UDPerror].chksum',
#  'UDPerror dport': 'packet[UDPerror].dport',
#  'UDPerror len': 'packet[UDPerror].len',
#  'UDPerror sport': 'packet[UDPerror].sport',
#  'MAC dst': 'packet.dst',
#  'packet layercount': 'len(packet.layers())',
#  'packet layers': '[i.__name__ for i in packet.layers()]',
#  'packet len': 'len(packet)',
#  'MAC src': 'packet.src',
#  'packet time': 'packet.time'}
