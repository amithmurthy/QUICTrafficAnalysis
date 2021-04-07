from scapy.utils import RawPcapNgReader
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from enum import Enum
import time
from datetime import datetime, date
from experiment import ClientTraffic, ServerTraffic
import pickle


class PktDirection(Enum):
    not_defined = 0
    client_to_server = 1
    server_to_client = 2


def printable_timestamp(ts, resol):
    ts_sec = ts // resol
    ts_subsec = ts % resol
    ts_sec_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts_sec))
    # return ts_sec_str, ts_subsec
    return '{}.{}'.format(ts_sec_str, ts_subsec)


def analyse_capture(Traffic, file_name):
    count = 0
    unique_addr_list = []
    server_pkt_size_sum = 0
    client_pkt_size_sum = 0
    server_pkt = 0
    client_pkt = 0
    for (pkt_data, pkt_metadata) in RawPcapNgReader(file_name):
        count += 1
        ether_pkt = Ether(pkt_data)

        #if ether_pkt.type != 0x0800:
            # Disregard non-IPv4 packets
            #continue
        if IP and UDP not in ether_pkt:
            continue
        ip_pkt = ether_pkt[IP]
        if ip_pkt.proto == 6:
            # Disreagrd non-UDP packets
            continue

        udp_pkt = ip_pkt[UDP]
        pkt_timestamp = (pkt_metadata.tshigh << 32) | pkt_metadata.tslow
        pkt_timestamp_resolution = pkt_metadata.tsresol
        pkt_ordinal = count
        if count == 1:
            if udp_pkt.sport != 6121:
                Traffic.client_port = udp_pkt.sport
            elif udp_pkt.dport != 6121:
                Traffic.client_port = udp_pkt.dport
            if ip_pkt.src == Traffic.client_ip and ip_pkt.dst != Traffic.client_ip:
                Traffic.server_ip = ip_pkt.dst
            #We need first packet to set the relative timestamp...
            first_pkt_timestamp = pkt_timestamp
            first_pkt_timestamp_resolution = pkt_timestamp_resolution
            first_pkt_ts = printable_timestamp(first_pkt_timestamp, first_pkt_timestamp_resolution)
            first_pkt_dt = datetime.strptime(first_pkt_ts, '%Y-%m-%d %H:%M:%S.%f')
            first_pkt_time = first_pkt_dt.time()
        timestamp = printable_timestamp(pkt_timestamp, pkt_timestamp_resolution)

        date_time_obj = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S.%f')

        this_pkt_ts = date_time_obj.time()
        this_pkt_relative_timestamp = datetime.combine(date.today(), this_pkt_ts) - datetime.combine(date.today(),
                                                                                                     first_pkt_time)
        direction = PktDirection.not_defined
        if ip_pkt.src == Traffic.client_ip:
            if udp_pkt.sport != int(Traffic.client_port):
                continue
            if ip_pkt.dst != Traffic.server_ip:
                continue
            if udp_pkt.dport != int(Traffic.server_port):
                continue
            direction = PktDirection.client_to_server
        elif ip_pkt.src == Traffic.server_ip:
            if udp_pkt.sport != int(Traffic.server_port):
                continue
            if ip_pkt.dst != Traffic.client_ip:
                continue
            if udp_pkt.dport != int(Traffic.client_port):
                continue
            direction = PktDirection.server_to_client
        else:
            continue
        # print(this_pkt_relative_timestamp)
        # Packet info is stored in a dict and then appended to list
        pkt_info = {}
        pkt_info['direction'] = direction
        pkt_info['ordinal'] = pkt_ordinal
        pkt_info['relative_timestamp'] = this_pkt_relative_timestamp
        pkt_info['size'] = len(udp_pkt)
        if len(udp_pkt) > 100:
            server_pkt += 1
        else:
            client_pkt += 1

        Traffic.packets_for_analysis.append(pkt_info)

        if direction == PktDirection.client_to_server:
            Traffic.client_to_server.append(pkt_info)
            client_pkt_size_sum += len(udp_pkt)
        elif direction == PktDirection.server_to_client:
            Traffic.server_to_client.append(pkt_info)
            server_pkt_size_sum += len(udp_pkt)

    print("server packets", server_pkt)
    print("client packets", client_pkt)

    ### Average Packet size calcs ###
    Traffic.server_pkt_bytes = server_pkt_size_sum
    Traffic.avg_server_pkt_size = server_pkt_size_sum / len(Traffic.server_to_client)
    Traffic.avg_client_pkt_size = client_pkt_size_sum / len(Traffic.client_to_server)
    # print("Server pkt bytes", Traffic.server_pkt_bytes)
    # print("client pkt size", Traffic.avg_client_pkt_size)
    # print("Analysed:", file_name)
    # calculate_throughput(Traffic)
    inter_arr_avg = 0
    pair_count = 0
    for i in range(0,len(Traffic.server_to_client),2):
        pair_count += 2
        first_pkt = Traffic.server_to_client[i]['relative_timestamp'].total_seconds()
        second_pkt = Traffic.server_to_client[i+1]['relative_timestamp'].total_seconds()
        inter_arrival_time = second_pkt - first_pkt
        inter_arr_avg += inter_arrival_time


    # print("Inter pakcet arrival time:",inter_arr_avg / pair_count)



def pickle_file(Traffic, pickle_file_out):

    with open(pickle_file_out, 'wb') as pickle_fd:
        pickle.dump(Traffic, pickle_fd)


def unpickle_file(Traffic, pickle_file_in):

    with open(pickle_file_in, 'rb') as pickle_fd:
        TrafficObj = pickle.load(pickle_fd)


def calculate_throughput(Traffic):
    # print("Calculating Tp, size of lists for file_obj: ", Traffic.server_ip, len(Traffic.server_to_client), len(Traffic.client_to_server))
    print("last client packet:", Traffic.client_to_server[-1]['relative_timestamp'].total_seconds())
    print("last server packet:", Traffic.server_to_client[-1]['relative_timestamp'].total_seconds())
    try:
        time_interval = Traffic.server_to_client[-1]['relative_timestamp'].total_seconds()
        ser_pkt_vol = len(Traffic.server_to_client)
        Traffic.server_throughput = Traffic.server_pkt_bytes / time_interval
        Traffic.client_throughput = len(Traffic.client_to_server) / time_interval
    except IndexError:
        print("List index out of range", IndexError)
        print("Server to client list is empty")
        pass
    print("Thorughput:", Traffic.server_throughput)
    # return server_throughput, client_throughput

def get_cpu_usage_average(cpu_data):
    cpu_val = []
    with open(cpu_data, 'r') as f:
        for line in f.read().split("\n")[1::6]:
            try:
                if(len(line.split()) > 0 ):
                    cpu = float(line.split()[-3])
                    cpu_val.append(cpu)
            except ValueError or IndexError:
                if ValueError:
                    print("ValueError", ValueError)
                elif IndexError:
                    print("ValueError", IndexError)
                    print(f, line)

    cpu_average = sum(cpu_val) / len(cpu_val)
    return cpu_average

def analyse_traffic_list(pcaps):
    server_files_server_tp = []
    server_files_client_tp = []
    client_files_server_tp = []
    client_files_client_tp = []
    for pcap in pcaps:
        pickle_file_out = pcap + ".pickle"
        if "server" in pcap:
            traffic_obj = ServerTraffic(pcap)
            analyse_capture(traffic_obj, pcap)
            server_files_server_tp.append(traffic_obj.server_throughput)
            server_files_client_tp.append(traffic_obj.client_throughput)
        elif "client" in pcap:
            traffic_obj = ClientTraffic(pcap)
            analyse_capture(traffic_obj, pcap)
            client_files_server_tp.append(traffic_obj.server_throughput)
            client_files_client_tp.append(traffic_obj.client_throughput)
        # pickle_file(traffic_obj, pickle_file_out)
    if len(server_files_client_tp) and len(server_files_server_tp) > 0:
        print(server_files_server_tp, server_files_client_tp)
        return server_files_server_tp, server_files_client_tp
    elif len(client_files_server_tp) and len(client_files_client_tp) > 0:
        print(client_files_server_tp, client_files_client_tp)
        return client_files_server_tp, client_files_client_tp




if __name__ == '__main__':
    tp_loss_client = ["mtu-comparison/tp/mtu12-noloss.pcapng", "mtu-comparison/tp/mtu12-0.1loss.pcapng","mtu-comparison/tp/mtu12-1loss.pcapng",
               "mtu-comparison/tp/mtu14-noloss.pcapng", "mtu-comparison/tp/mtu14-0.1loss.pcapng","mtu-comparison/tp/mtu14-1loss.pcapng"]
    # tp_loss_server = []
    # file_in =  + ".pcapng"  # Enter name of pcap file to analyse
    # pickle_file_out = file_in[:-7] + ".pickle"


    cc20_server_tp = []
    cc20_mtu12_traffic = ["cc20/cc20-mtu12/client1KB.pcapng","cc20/cc20-mtu12/client10KB.pcapng","cc20/cc20-mtu12/client1MB.pcapng", "cc20/cc20-mtu12/client10MB.pcapng","cc20/cc20-mtu12/client100MB.pcapng"]
    cc20_mtu14_traffic = ["cc20/cc20-mtu14/client1KB.pcapng","cc20/cc20-mtu14/client10KB.pcapng","cc20/cc20-mtu14/client1MB.pcapng", "cc20/cc20-mtu14/client10MB.pcapng","cc20/cc20-mtu14/client100MB.pcapng"]
    aes_mtu14_traffic = ["aes/mtu14/client1KB.pcapng", "aes/mtu14/client10KB.pcapng","aes/mtu14/client1MB.pcapng", "aes/mtu14/client10MB.pcapng","aes/mtu14/client100MB.pcapng"]
    aes_mtu12_traffic = ["aes/mtu12/client1KB.pcapng", "aes/mtu12/client10KB.pcapng","aes/mtu12/client1MB.pcapng", "aes/mtu12/client10MB.pcapng","aes/mtu12/client100MB.pcapng"]
    # default_test = ClientTraffic("default100MB.pcapng")
    # analyse_capture(default_test, "default100MB.pcapng")
    # aes_stp.append(default_test.server_throughput)
    # aes_ctp.append(default_test.client_throughput)

    # analyse_traffic_list(aes_mtu12_traffic)


    # analyse_capture(file_in)
    # pickle_file(pickle_file_out)
    # s_tp, c_tp = calculate_throughput()

    # pickle_file(default_test, pickle_file_out)
    cc20_mtu14_avg = []
    mtu12_cpu_avg = []
    mtu14_cpu_avg = []
    ##
    aes_mtu12_cpu = ["CPU/mtu1200/mtumin-1KB.txt", "CPU/mtu1200/mtumin-10KB.txt", "CPU/mtu1200/mtumin-1MB.txt", "CPU/mtu1200/mtumin-10MB.txt", "CPU/mtu1200/mtumin-100MB.txt"]
    aes_mtu14_cpu = ["CPU/mtu1400/10KB.txt", "CPU/mtu1400/1MB.txt", "CPU/mtu1400/10MB.txt", "CPU/mtu1400/100MB.txt"]
    cc20_mtu12_cpu = ["cc20/CPU/cc20mtu12-1KB.txt", "cc20/CPU/cc20mtu12-10KB.txt", "cc20/CPU/cc20mtu12-1MB.txt", "cc20/CPU/cc20mtu12-10MB.txt", "cc20/CPU/cc20mtu12-100MB.txt"]
    cc20_mtu14_cpu = ["cc20/CPU/cc20mtu14-1KB.txt", "cc20/CPU/cc20mtu14-10KB.txt", "cc20/CPU/cc20mtu14-1MB.txt", "cc20/CPU/cc20mtu14-10MB.txt", "cc20/CPU/cc20mtu14-100MB.txt"]
    # cc20_mtu14_avg = []

    for f in cc20_mtu12_cpu:
        mtu12_cpu_avg.append(get_cpu_usage_average(f))

    for i in cc20_mtu14_cpu:
        mtu14_cpu_avg.append(get_cpu_usage_average(i))

    print("1200 mtu:", mtu12_cpu_avg)
    print("1400 mtu:", mtu14_cpu_avg)
