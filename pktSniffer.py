import argparse
import pyshark 

def main():
    """
     Main function that analyzes Pcap network files and print out info
     based on provided filters.

     Arguments: None
     Returns:None 

    Use Pyshark Library along with OS to read in and create a dictionary for each packet.
    The keys are the name of the attribute and the value is the data itself.
    All packets are stored in a list called "Packets" before being filtered and printed.
    """

    parser = argparse.ArgumentParser()
    parser.add_argument("-host")
    parser.add_argument("-ip", action='store_true')
    parser.add_argument("-r")
    parser.add_argument("-port")
    parser.add_argument("-c")
    parser.add_argument("-tcp", action='store_true')
    parser.add_argument("-udp", action='store_true')
    parser.add_argument("-icmp", action='store_true')
    parser.add_argument("-net")
    args = parser.parse_args()
    cap = pyshark.FileCapture(args.r)   
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
        if hasattr(packet,"udp"):
                currPacket["udpSrc"] = packet.udp.srcport
                currPacket["udpDst"] = packet.udp.srcport
        if hasattr(packet, "icmp"):
                currPacket["icmpType"] = packet.icmp.type
                currPacket["icmpCode"] = packet.icmp.code
        packets.append(currPacket)
    packetCounter = 0

    """
   
    """

    """
    Here all packets have been read in and organized.
    We check and apply all command line filters and append it to another list 
    called "output packets"
    """
    outputPackets = []
    for packet in packets:
            if args.host:
                   if "sourceIp" in packet:
                    if (packet["sourceIp"]) == args.host:
                        if packet not in outputPackets:
                            outputPackets.append(packet)
                    elif (packet["destinationIp"] == args.host):
                        if packet not in outputPackets:
                            outputPackets.append(packet)
            if args.port:
                if "tcpSrc" in packet:
                    if (packet["tcpSrc"]) == args.port:
                        if packet not in outputPackets:
                            outputPackets.append(packet)
                    elif (packet["tcpDst"] == args.port) or (packet["tcpDst"]) == args.port:
                        if packet not in outputPackets:
                            outputPackets.append(packet)
                if "udpSrc" in packet:
                    if (packet["udpSrc"]) == args.port:
                        if packet not in outputPackets:
                            outputPackets.append(packet)
                    elif  (packet["udpDst"]) == args.port:
                        if packet not in outputPackets:
                            outputPackets.append(packet)
            if args.ip:
                if "Ipversion" in packet:
                    if packet["Ipversion"] == "4":
                        outputPackets.append(packet)
            if args.tcp:
                if "tcpSrc" in packet:
                    if packet not in outputPackets:
                            outputPackets.append(packet)
            if args.udp:
                if "udpSrc" in packet:
                    if packet not in outputPackets:
                            outputPackets.append(packet)
            if args.icmp:
                 if "icmpType" in packet:
                    if packet not in outputPackets:
                            outputPackets.append(packet)
            if args.net:
                 temp = args.net.split(".")
                 targetNet = ".".join(temp[:-1])
                 if "sourceIp" in packet:
                    temp = packet["sourceIp"].split(".")
                    genSrc = ".".join(temp[:-1])
                    temp = packet["destinationIp"].split(".")
                    genDst = ".".join(temp[:-1])
                    if targetNet == genSrc or targetNet == genDst:
                        if packet not in outputPackets:
                            outputPackets.append(packet)
            if (not args.host and not args.port and not args.ip and not args.tcp and not args.udp and not args.icmp and not args.net):
                 outputPackets.append(packet) 
    
    """
    The -c or counter flag is checked after all other filters have been applied. 
    Here I used the printPackets function too figure out how much of the output the user wants 
    before displaying. 
    """
    if args.c:
        printPackets(outputPackets, args.c)
    else:
        printPackets(outputPackets, 0)


def printPackets(outputPackets,c):
    """
    Function that takes the list of all packets needed to be displayed and prints them to 
    stdout.

    Parameters: 
    <Dict> List outputPackets: Contains all the packets that remain after filters have been applied
                               Each index of the array is a dictionary holding 1 packet of information
            int Counter:       This is the argument the user passed in when using the -c flag
                               Limists the output to C packets  
    """
    loop = 0
    if c != 0:
        loop = int(c)
    else:
        loop = len(outputPackets)
    if len(outputPackets) != 0:
        for x in range(loop):   
            print(outputPackets[x])
            
    


 
if __name__ == "__main__":
    main()


