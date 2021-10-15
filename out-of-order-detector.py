import os
import pyshark
from subprocess import call
from tqdm import tqdm

ports, repeatedExists, prev_seq, isOutOfOrder, newOrderStarter, analyzedPackets, affectedPackets, affectedRanges = [], False, None, False, False, [], [], []
capture_file = "2021_10-06-11-20"

if not os.path.exists('original_pcaps'):
    os.makedirs('original_pcaps')

if not os.path.exists(capture_file + "-fixed.pcap"):
    fix_cut_packet = call(["python", "pcap-fix.py", "--in", capture_file + ".pcap", "--pcapfix", "--pcapfix_dir", "original_pcaps", "--debug"])

cap = pyshark.FileCapture(capture_file + "-fixed.pcap", display_filter='udp')

print("Reading ports")
ports = [p[p.transport_layer].dstport for p in tqdm(cap) if p[p.transport_layer].dstport != "53"]

if repeatedExists == False:
    for x in range(len(ports)):
        if ports.count(ports[x]) > 1:
            repeatedExists = True

if repeatedExists:
    ports = set(ports)

print("Analyzing traces...")
for port in tqdm(ports):
    rtp_cap = pyshark.FileCapture(capture_file + "-fixed.pcap", display_filter='rtp', decode_as={'udp.port==' + port: 'rtp'})
    # rtp_cap.set_debug()
    for rtp_packet in rtp_cap:
        length = rtp_packet.length
        if length == "85":
            seq = int(rtp_packet.rtp.seq)
            ssrc = rtp_packet.rtp.ssrc

            if prev_seq == None:
                prev_seq = seq
                prev_ssrc = ssrc

            elif seq < prev_seq and ssrc == prev_ssrc:
                isOutOfOrder = True
                
                if analyzedPackets[-1][-2] == False:
                    newOrderStarter = True

            elif seq == prev_seq + 1:
                prev_seq = seq
                prev_ssrc = ssrc

            elif seq != prev_seq + 1 and seq > prev_seq:
                prev_seq = seq
                prev_ssrc = ssrc
                
                if isOutOfOrder == True:
                    isOutOfOrder = False

                # print(rtp_packet.number, "Packets dropped")

            elif prev_seq == 65535 and seq == 0:
                prev_seq = seq
                prev_ssrc = ssrc
                # print(rtp_packet.number, "seq_num turnover")

            analyzedPackets.append([rtp_packet.number, seq, isOutOfOrder, newOrderStarter])
            isOutOfOrder = False
            newOrderStarter = False

    rtp_cap.close()
    prev_seq = None

# if analyzedPackets:
#     affectedPackets = [packet[0] for packet in analyzedPackets if packet[-2] == True]
#     starters = [packet[0] for packet in analyzedPackets if packet[-1] == True]
   
print("-----------------------------")

if analyzedPackets:
    for packet in analyzedPackets:
        if packet[-1] == True:
            starter = packet
        elif packet[-1] != True and packet[-2] == True:
            affected = packet
        elif packet[0] != analyzedPackets[0][0] and packet[-2] == False and analyzedPackets[analyzedPackets.index(packet) - 1][-2] == True:
            last = analyzedPackets[analyzedPackets.index(packet) - 1]
            affectedRanges.append([starter, last])

    for x in affectedRanges:
        if affectedRanges.count(x) > 1:
            affectedRanges.remove(x)

    print("The following ranges are out of order:")

    for affectedRange in sorted(affectedRanges, key=lambda x:x[0], reverse=True):
        print("frame", affectedRange[0][0], "-", affectedRange[1][0], "| seq_num", affectedRange[0][1], "-", affectedRange[1][1])
