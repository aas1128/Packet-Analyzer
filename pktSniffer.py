import argparse
import pyshark 

def main():
    parser = argparse.ArgumentParser()

    parser.add_argument("fileName")
    parser.add_argument("-host")
    parser.add_argument("ip", action="store_true")
    parser.add_argument("-r")
    parser.add_argument("-port")
    parser.add_argument("-c")
    



    args = parser.parse_args()
    cap = pyshark.FileCapture(args.fileName)

    # Print all packet details
    for packet in cap:


        if hasattr(packet, 'eth'):
            size = packet.length
            dest_mac_addr= packet.eth.dst
            src_mac_addr = packet.eth.src
            type = packet.eth.type
        
        if hasattr(packet, "ip"):
             Ipversion = packet.ip.version
             headerLen = packet.ip.hdr_len
             typeOfServie = packet.ip.dsfield
             ipLen = packet.ip.len
             identification = packet.ip.id
             flags = packet.ip.flags
             fragmentOffset = packet.ip.frag_offset
             timeTolive = packet.ip.ttl
             protocol = packet.ip.proto
             checkSum = packet.ip.checksum
             sourceIp = packet.ip.src
             destinationIp = packet.ip.dst

             if hasattr(packet,"tcp"):
                 tcpSrc = packet.tcp.srcport
                 tcpDst = packet.tcp.dstport
             elif hasattr(packet,"udp"):
                udpSrc = packet.udp.srcport
                print(udpSrc)
                udpDst = packet.udp.srcport
             elif hasattr(packet, "icmp"):
                icmpSrc = packet.icmp.srcport
                print(icmpSrc)
                icmpDst = packet.icmp.dstport
                print(icmpDst)




    # print("Ethernet Header:")
    # print("Packet size: ", size)
    # print("Destination MAC address", dest_mac_addr)
    # print("Source MAC address", src_mac_addr)
    # print("Ethertype", type)

    # print("\n\n\n\n\n")
    # print("IP Header:")
    # print("Version: ", Ipversion)
    # print("Header Length: ", headerLen)
    # print("Type of Service: ", typeOfServie)
    # print("Total Length: ", ipLen)
    # print("Identification: ", identification)
    # print("Flags: ", flags)
    # print("Fragment Offset: ", fragmentOffset)
    # print("Time to Live: ", timeTolive)
    # print("Protocol: ", protocol)
    # print("Header CheckSum: ", checkSum)
    # print("Source IP: ", sourceIp)
    # print("Destination IP: ", destinationIp)
    # print("\n\n\n\n\n")

    # print("Encapsulated Packets:")
    # print("TCP:")
    # print("SRC: ", tcpSrc)
    # print("DST: ", tcpDst)






    




main()


