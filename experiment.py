

class ClientTraffic():

    def __init__(self, file_in):
        self.client_ip = '192.168.1.127'
        self.server_ip = None
        self.server_port = 6121
        self.client_port = None
        self.packets_for_analysis = []
        self.client_to_server = []
        self.server_to_client = []
        #self.analyse_capture(file_in)
        #self.pickle_file_out = str(file_in[:-7]) + ".pickle"
        #self.pickle_file(self.pickle_file_out)
        self.server_throughput = None
        self.client_throughput = None
        self.avg_server_pkt_size = None
        self.avg_client_pkt_size = None
        self.server_pkt_bytes = None


class ServerTraffic():

    def __init__(self, file_in ):
        self.client_ip = '47.72.135.73'
        self.server_ip = None
        self.server_port = 6121
        self.client_port = None
        self.packets_for_analysis = []
        self.client_to_server = []
        self.server_to_client = []
        #self.analyse_capture(file_in)
        # self.pickle_file_out = str(file_in[:-7]) + ".pickle"
        # self.pickle_file(self.pickle_file_out)
        self.server_throughput = None
        self.client_throughput = None
        self.avg_server_pkt_size = None
        self.avg_client_pkt_size = 0
