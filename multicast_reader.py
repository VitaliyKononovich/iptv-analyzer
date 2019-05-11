import argparse
import socket
import datetime
from ts.ts_reader import TSReader
from ts.ts_stat import Statistics
from views.viever import Viewer


def multicast_reader():
    # Create the socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 32)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
    #print(sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF))
    #sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, RECV_BUFSIZE)
    print('Socket RCVBUF={}'.format(sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)))

    # Bind to the server address
    host = socket.gethostbyname(socket.gethostname())
    sock.bind((host, MCAST_PORT))

    # Create TSReader object
    viewer = Viewer()
    stats = Statistics(pcap=True, interval_s=STAT_INTERVAL_S, skip_cc_err_for_first_ms=SKIP_CC_ERR_FOR_FIRST_MS)
    stats.onStatReady += viewer.print_stat_result
    stats.onFinalStatReady += viewer.print_final_stat_result
    ts_reader = TSReader()
    ts_reader.onPacketDecoded += stats.update_stat
    ts_reader.onPatReceived += stats.update_programs_info
    ts_reader.onPmtReceived += stats.update_programs_info
    ts_reader.onCatReceived += stats.update_programs_info
    ts_reader.onProgramSdtReceived += stats.update_programs_info
    # ts_reader.onSdtReceived += stats.update_programs_info
    # ts_reader.onBatReceived += stats.update_programs_info
    # ts_reader.onNitReceived += stats.update_programs_info

    # Prepare write to ts file
    if WRITE_TO_FILE:
        out_ts = open(MCAST_GRP + '.ts', 'wb')

    # Tell the operating system to add the socket to the multicast group
    # on HOST interfaces.
    mreq = socket.inet_aton(MCAST_GRP) + socket.inet_aton(host)
    stats.monitoring_start_dt = datetime.datetime.now()
    sock.settimeout(TIME_TO_WAIT_MULTICAST_S)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

    print('START MONITORING: {}'.format(stats.monitoring_start_dt))
    first_packet = True
    is_multicast_present = False    # Changed to True if multicast present

    # Receive/respond loop
    try:
        while True:
            data = sock.recv(BUFSIZE)
            is_multicast_present = True
            #data, address = sock.recvfrom(BUFSIZE)
            dt = datetime.datetime.now()
            if first_packet:
                first_packet = False
                print('JOIN TIME: {}s'.format((dt - stats.monitoring_start_dt).total_seconds()))
            if (dt - stats.monitoring_start_dt).total_seconds() > MOMITORING_TIME_S:
                break
            #print('{} - {}'.format(dt, data.hex()))
            ts_reader.read(data, dt=dt)
            if WRITE_TO_FILE:
                out_ts.write(data)
    except socket.timeout:
        pass

    stats.monitoring_end_dt = datetime.datetime.now()
    stat = stats.get_stat()
    print('\nSTOP MONITORING: {}\n'.format(stats.monitoring_end_dt))
    if is_multicast_present:
        if stats.pat_received_dt is not None:
            viewer.print_pat(stats.programs.pat, stats.pat_received_dt)
        if stats.pmt_received_dt is not None:
            for pid in stats.programs.get_pmt_pids():
                viewer.print_pmt(stats.programs.get_prog_pmt(pid), stats.pmt_received_dt)
        if stats.sdt_received_dt is not None:
            viewer.print_sdt(stats.programs.sdt, stats.sdt_received_dt)
        if stats.cat_received_dt is not None:
            viewer.print_cat(stats.programs.cat, stats.cat_received_dt)
        viewer.print_stat(stat, stats.programs, ts_reader.known_pids)
    else:
        print('NO MULTICAST FOUND!!!')

    # Close write to file
    if WRITE_TO_FILE:
        out_ts.close()


if __name__ == "__main__":
    """Subscribe to multicast stream and monitor its parameters according to ETSI TR 101 290"""
    parser = argparse.ArgumentParser(description='Subscribe to multicast stream and monitor its paramiters '
                                                 + 'according to ETSI TR 101 290')
    parser.add_argument('-i', '--ipaddress', nargs='?', required=True, help='multicast ip address')
    parser.add_argument('-p', '--port', nargs='?', type=int, default=1234, help='multicast port')
    parser.add_argument('-w', '--wait_s', nargs='?', type=int, default=15, help='time to wait multicast in seconds')
    parser.add_argument('-t', '--mon_time_s', nargs='?', type=int, default=180, help='monitoring time in seconds')
    parser.add_argument('-s', '--stat_int_s', nargs='?', type=int, default=1,
                        help='statistics output interval in seconds')
    parser.add_argument('-e', '--skip_cc_err_ms', nargs='?', type=int, default=500,
                        help='skipping CC errors for first milliseconds')
    args = vars(parser.parse_args())

    MCAST_GRP = args['ipaddress']
    MCAST_PORT = args['port']
    # RECV_BUFSIZE = 16384
    BUFSIZE = 1358
    MOMITORING_TIME_S = args['mon_time_s']
    TIME_TO_WAIT_MULTICAST_S = 15
    STAT_INTERVAL_S = args['stat_int_s']
    SKIP_CC_ERR_FOR_FIRST_MS = args['skip_cc_err_ms']
    WRITE_TO_FILE = False

    multicast_reader()
