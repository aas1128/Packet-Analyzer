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
    packets = []
    for packet in cap:
        currPacket = {}
        if hasattr(packet, 'eth'):
            currPacket["size"] = packet.length
            currPacket["dest_mac_addr"] = packet.eth.dst
            currPacket["src_mac_addr"] = packet.eth.src
            currPacket["type"] = packet.eth.type
        
        if hasattr(packet, "ip"):
             currPacket["Ipversion"] = packet.ip.version
             currPacket["headerLen"] = packet.ip.hdr_len
             currPacket["typeOfServie"] = packet.ip.dsfield
             currPacket["ipLen"] = packet.ip.len
             currPacket["identification"] = packet.ip.id
             currPacket["flags"] = packet.ip.flags
             currPacket["fragmentOffset"] = packet.ip.frag_offset
             currPacket["timeTolive"] = packet.ip.ttl
             currPacket["protocol"] = packet.ip.proto
             currPacket["heckSum"] = packet.ip.checksum
             currPacket["sourceIp"] = packet.ip.src
             currPacket["destinationIp"] = packet.ip.dst

             if hasattr(packet,"tcp"):
                 currPacket["tcpSrc"] = packet.tcp.srcport
                 currPacket["tcpDst"] = packet.tcp.dstport
             elif hasattr(packet,"udp"):
                currPacket["udpSrc"] = packet.udp.srcport
                currPacket["udpDst"] = packet.udp.srcport
             elif hasattr(packet, "icmp"):
                currPacket["icmpSrc"] = packet.icmp.srcport
                currPacket["icmpDst"] = packet.icmp.dstport
        packets.append(currPacket)
        print(packets)




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


