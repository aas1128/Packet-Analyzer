Project: Packet-Analyzer
Description: This program is a network packet anaylzer that reads packets and displays them.
             It has been extended to allow filtering by using command line prompts.

1) How to compile and run the code:
    1) Clone the github repository to access the python code and the dependencies (can make a virtual environment using python)
    2) Check if python is downloaded on the system
    3) install the requirements needed to run the code 
    4) run the code using "python pktsniffer.py" follow by filters if wanted

2) Possible command line arguments:

    "-Host": User provides a host IP and the program will filter packets based on if source IP/ desntination IP matches

    "-Port": User provides a port number and the program will filter packets based on matching tcp/udp destination and source ports

    "-IP": User provides a IP address and the program will filter packets based on the IP identification number

    "-tcp": User provides a tcp port and the program filters packets based on if they match the source/destination port.

    "-udp": User provides a tcp port and the program filters packets based on if they match the source/destination port.

    "-icmp": User provides a tcp port and the program filters packets based on if they match the source/destination port.

    "-net": User provides an network address and if there are packets with similar sourse/destination ports they are displayed

    "-c": Counter a user can provide to limit the amount of packets being displayed in the output window.


