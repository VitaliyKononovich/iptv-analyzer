import sys
import os
from models import *
from dicts import dict_reader


class Viewer:
    def __init__(self):
        # Load Dictionary
        cwd = os.getcwd()
        self.__stream_type = dict_reader.load_dictionary_csv(os.path.join(cwd, 'dicts', 'stream_type.csv'))
        self.__table_id = dict_reader.load_dictionary_csv(os.path.join(cwd, 'dicts', 'table_id.csv'))
        self.__service_type = dict_reader.load_dictionary_csv(os.path.join(cwd, 'dicts', 'service_type.csv'))
        self.__descriptor_tag = dict_reader.load_dictionary_csv(os.path.join(cwd, 'dicts', 'descriptor_tag.csv'))

    def print_pat(self, pat: PAT, dt=None, file=None):
        if file is None:
            file = sys.stdout
        print('Program Association Table ({})'.format(dt), file=file)
        print('\t{:<25}0x{:02X} - {}'.format('Table ID:', pat.table_id, dict_reader.find(self.__table_id, pat.table_id),
                                             file=file))
        print('\t{:<25}0x{:04X}'.format('Transport stream ID:', pat.ts_id), file=file)
        print('\t{:<25}0x{:02X}'.format('Version number:', pat.ver_num), file=file)
        print('\t{:<25}0x{:02X}'.format('Current Next Indicator:', pat.cur_next_ind), file=file)
        print('\t{:<25}0x{:02X}'.format('Section Number:', pat.sec_num), file=file)
        print('\t{:<25}0x{:02X}'.format('Last Section Number:', pat.last_sec_num), file=file)
        print('\tProgram numbers:', file=file)
        for prog in pat.prog_nums:
            if prog['program_number'] == 0:
                print('\t\tProgram_number=0x{:04X}, network_PID=0x{:04X}, program_map_PID=None'.format(
                            prog['program_number'], prog['network_PID']), file=file)
            else:
                print('\t\tProgram_number=0x{:04X}, network_PID=None, program_map_PID=0x{:04X}'.format(
                            prog['program_number'], prog['program_map_PID']), file=file)
        print('\n', file=file)

    def print_pmt(self, pmt: PMT, dt=None, file=None):
        if file is None:
            file = sys.stdout
        print('Program Map Table ({})'.format(dt), file=file)
        print('\t{:<25}0x{:02X} - {}'.format('Table ID:', pmt.table_id, dict_reader.find(self.__table_id, pmt.table_id),
                                             file=file))
        print('\t{:<25}0x{:04X}'.format('Program number:', pmt.prog_num), file=file)
        print('\t{:<25}0x{:02X}'.format('Version number:', pmt.ver_num), file=file)
        print('\t{:<25}0x{:02X}'.format('Current Next Indicator:', pmt.cur_next_ind), file=file)
        print('\t{:<25}0x{:02X}'.format('Section Number:', pmt.sec_num), file=file)
        print('\t{:<25}0x{:02X}'.format('Last Section Number:', pmt.last_sec_num), file=file)
        print('\t{:<25}0x{:04X}'.format('PCR PID:', pmt.pcr_pid), file=file)
        print('\tDescriptors:', file=file)
        for descriptor in pmt.descriptors:
            print('\t\tDescriptor tag=0x{:02X} - {}'.format(descriptor['descriptor_tag'],
                                                            dict_reader.find(self.__descriptor_tag,
                                                            descriptor['descriptor_tag'])), file=file)
            print('\t\tDescriptor data={}'.format(descriptor['descriptor_data']), file=file)
        print('\tStreams:', file=file)
        for stream in pmt.streams:
            print('\t\tStream PID=0x{:04X}, Stream type=0x{:04X} - {}'.format(
                        stream['elementary_pid'], stream['stream_type'],
                        dict_reader.find(self.__stream_type, stream['stream_type'])), file=file)
        print('\n', file=file)

    def print_sdt(self, sdt: SDT, dt=None, file=None):
        if file is None:
            file = sys.stdout
        print('Service Description Table ({})'.format(dt), file=file)
        print('\t{:<25}0x{:02X} - {}'.format('Table ID:', sdt.table_id, dict_reader.find(self.__table_id, sdt.table_id),
                                             file=file))
        print('\t{:<25}0x{:04X}'.format('Transport Stream ID:', sdt.transport_stream_id), file=file)
        print('\t{:<25}0x{:02X}'.format('Version number:', sdt.ver_num), file=file)
        print('\t{:<25}0x{:02X}'.format('Current Next Indicator:', sdt.cur_next_ind), file=file)
        print('\t{:<25}0x{:02X}'.format('Section Number:', sdt.sec_num), file=file)
        print('\t{:<25}0x{:02X}'.format('Last Section Number:', sdt.last_sec_num), file=file)
        print('\t{:<25}0x{:02X}'.format('Original Network ID:', sdt.original_network_id), file=file)
        print('\tServices:', file=file)

        running_status = ['undefined', 'not running', 'starts in a few seconds', 'pausing', 'running',
                          'service off-air', 'reserved for future use', 'reserved for future use']
        for service in sdt.services:
            print('\t\tService ID=0x{:04X}'.format(service['service_id']), file=file)
            print('\t\t\tEIT_schedule_flag={}'.format(service['EIT_schedule_flag']), file=file)
            print('\t\t\tEIT_present_following_flag={}'.format(service['EIT_present_following_flag']), file=file)
            print('\t\t\tRunning_status={} - {}'.format(service['running_status'],
                                                        running_status[service['running_status']]), file=file)
            print('\t\t\tFree_CA_mode={}'.format(service['free_CA_mode']), file=file)
            for descriptor in service['descriptors']:
                print('\t\t\tDescriptor tag=0x{:02X} - {}'.format(descriptor['descriptor_tag'],
                                    dict_reader.find(self.__descriptor_tag, descriptor['descriptor_tag'])), file=file)
                print('\t\t\tDescriptor data={}'.format(descriptor['descriptor_data']), file=file)
        print('\n', file=file)

    def print_cat(self, cat: CAT, dt=None, file=None):
        if file is None:
            file = sys.stdout
        print('Conditional Access Table ({})'.format(dt), file=file)
        print('\t{:<25}0x{:02X} - {}'.format('Table ID:', cat.table_id,
                                             dict_reader.find(self.__table_id, cat.table_id),
                                             file=file))
        print('\t{:<25}0x{:02X}'.format('Version number:', cat.ver_num), file=file)
        print('\t{:<25}0x{:02X}'.format('Current Next Indicator:', cat.cur_next_ind), file=file)
        print('\t{:<25}0x{:02X}'.format('Section Number:', cat.sec_num), file=file)
        print('\t{:<25}0x{:02X}'.format('Last Section Number:', cat.last_sec_num), file=file)
        print('\tDescriptors:')
        for descriptor in cat.descriptors:
            print('\t\t\tDescriptor tag=0x{:02X} - {}'.format(descriptor['descriptor_tag'],
                                                              dict_reader.find(self.__descriptor_tag,
                                                                               descriptor['descriptor_tag'])),
                  file=file)
            print('\t\t\tDescriptor data={}'.format(descriptor['descriptor_data']), file=file)
        print('\n', file=file)

    def print_bat(self, bat: BAT, dt=None, file=None):
        if file is None:
            file = sys.stdout
        print('Bouquet Association Table  ({})'.format(dt), file=file)
        print('\t{:<25}0x{:02X} - {}'.format('Table ID:', bat.table_id, dict_reader.find(self.__table_id, bat.table_id),
                                             file=file))
        print('\t{:<25}0x{:04X}'.format('Bouquet ID:', bat.bouquet_id), file=file)
        print('\t{:<25}0x{:02X}'.format('Version number:', bat.ver_num), file=file)
        print('\t{:<25}0x{:02X}'.format('Current Next Indicator:', bat.cur_next_ind), file=file)
        print('\t{:<25}0x{:02X}'.format('Section Number:', bat.sec_num), file=file)
        print('\t{:<25}0x{:02X}'.format('Last Section Number:', bat.last_sec_num), file=file)
        print('\tBouquet descriptors:')
        for descriptor in bat.descriptors:
            print('\t\tDescriptor tag=0x{:02X} - {}'.format(descriptor['descriptor_tag'],
                                                              dict_reader.find(self.__descriptor_tag,
                                                                               descriptor['descriptor_tag'])),
                  file=file)
            print('\t\tDescriptor data={}'.format(descriptor['descriptor_data']), file=file)
        print('\tTransport streams:')
        for ts in bat.transport_streams:
            print('\t\tTransport stream ID=0x{:04X}'.format(ts['transport_stream_id']), file=file)
            print('\t\tOriginal network ID=0x{:04X}'.format(ts['original_network_id']), file=file)
            print('\t\tDescriptors:')
            for descriptor in ts['descriptors']:
                print('\t\t\tDescriptor tag=0x{:02X} - {}'.format(descriptor['descriptor_tag'],
                                    dict_reader.find(self.__descriptor_tag, descriptor['descriptor_tag'])), file=file)
                print('\t\t\tDescriptor data={}'.format(descriptor['descriptor_data']), file=file)
        print('\n', file=file)

    def print_stat(self, stat, programs: Programs, known_pids: list, file=None):
        print('\nProgram statistic:', file=file)
        self._print_stat({'pid': -1, 'bitrate': stat['program_bitrate'], 'stat': stat['program_stat']}, file)

        print('\nTS statistic:', file=file)
        pids_stat = sorted(stat['pids'], key=lambda k: k['pid'])
        for pid in pids_stat:
            self._print_stat(pid, file)

        pids = set([pid['pid'] for pid in stat['pids']])
        pids -= (programs.get_pmt_pids() | programs.get_stream_pids()
                 | programs.get_other_pids() | programs.get_net_pids()
                 | known_pids)
        if len(pids) > 0:
            print('\nUnknown PIDs:', file=file)
            for pid in sorted(pids):
                print('\tPID=0x{:04X}'.format(pid), file=file)

    def _print_stat(self, pid, file):
        print(
            '\t{}\t bitrate={:<10} stat: packet_count={:<10} strambled_packets={:<3} rsync={:<3} PAT_error={}  CC_errors={}  PMT_error={}  PID_error={}  Transport_error={}  CRC_error={}  PCR_Error1={}  PCR_Error2={},  PTS_error={},  CAT_error={}'.format(
                (' '*10 if pid['pid'] == -1 else 'PID=0x{:04X}'.format(pid['pid'])), pid['bitrate'],
                pid['stat']['Packet_count'], pid['stat']['Scrambled_count'], pid['stat']['TS_sync_loss'],
                pid['stat']['PAT_error'], pid['stat']['CC_errors'], pid['stat']['PMT_error'], pid['stat']['PID_error'],
                pid['stat']['Transport_error'], pid['stat']['CRC_error'], pid['stat']['PCR_repetition_error'],
                pid['stat']['PCR_discontinuity_indicator_error'], pid['stat']['PTS_error'], pid['stat']['CAT_error']),
            file=file)

    def print_stat_result(self, stat_result, file=None):
        print(stat_result, file=file)

    def print_final_stat_result(self, stat_result, file=None):
        print(stat_result, file=file)
