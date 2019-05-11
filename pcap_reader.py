import struct
import datetime
from ts.ts_reader import TSReader
from ts.ts_stat import Statistics
from views.viever import Viewer


#source_file = r'c:\Users\vitaliy_ko\PycharmProjects\iptv\samples\setanta2.pcap'
source_file = input('Please enter full path to pcap-file: ')

# out = open('test.ts', 'wb')

with open(source_file, 'rb') as f:
    f.read(24)  # read pcap global header
    viewer = Viewer()
    stats = Statistics(pcap=True, interval_s=10)
    stats.onStatReady += viewer.print_stat_result
    stats.onFinalStatReady += viewer.print_final_stat_result
    ts_reader = TSReader()
    ts_reader.onPacketDecoded += stats.update_stat
    ts_reader.onPatReceived += stats.update_programs_info
    ts_reader.onPmtReceived += stats.update_programs_info
    ts_reader.onCatReceived += stats.update_programs_info
    ts_reader.onProgramSdtReceived += stats.update_programs_info
    #ts_reader.onSdtReceived += stats.show_table_data
    #ts_reader.onBatReceived += stats.show_table_data
    #ts_reader.onNitReceived += stats.show_table_data

    while True:
        # packet_header
        b = f.read(8)  # time sec usec
        if b == b'':
            break
        sec, usec = struct.unpack('=LL', b)
        dt = datetime.datetime.fromtimestamp(sec) + datetime.timedelta(microseconds=usec)
        plen, empty = struct.unpack('=LL', f.read(8))
        data = f.read(plen)
        # 14 (ethernet header) + 10 (IP header - protocol byte)
        if int(data[23]) == 17:  # 17 UDP
            # + 10 (rest of IP header) + 8 (UDP header)
            data = data[42:]
            # print('{} - {}'.format(dt, data.hex()))
            # ts_reader.read(data, dt=dt, parse_SDT=True, parse_BAT=True)
            ts_reader.read(data, dt=dt)
           #  out.write(data)

    stat = stats.get_stat()
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

# out.close()
