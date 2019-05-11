from models.TSPacket import TSPacket
from models.Programs import Programs
from views.viever import Viewer
import datetime
import threading
import copy
import json
from events.event import Event

"""
ETSI TR 101 290 V1.3.1 - Digital Video Broadcasting (DVB); Measurement guidelines for DVB systems
"""


class PidStat:
    """ Class for collecting statistics per PID based on ETSI TR 101 290 V1.3.1 """
    def __init__(self):
        self.Packet_count = 0
        self.Scrambled_count = 0

        # First priority: necessary for decodability (basic monitoring)
        self.TS_sync_loss = 0
        self.Sync_byte_error = 0
        self.PAT_error = 0
        self.CC_errors = 0
        self.PMT_error = 0
        self.PID_error = 0

        # Second priority: recommended for continuous or periodic monitoring
        self.Transport_error = 0
        self.CRC_error = 0
        self.PCR_repetition_error = 0
        self.PCR_discontinuity_indicator_error = 0
        self.PTS_error = 0
        self.CAT_error = 0

        # Additional variables for stat calculation
        self.x_pam_dt = None
        self.x_pmt_dt = None
        self.x_pid_dt = None
        self.x_pcr_dt = None
        self.x_pts_dt = None
        self.cc = None
        self.x_cc_repeated = False

    def __str__(self):
        lst = ['{"Packet_count":', str(self.Packet_count),
               ',"Scrambled_count":', str(self.Scrambled_count),
               ',"TS_sync_loss":', str(self.TS_sync_loss),
               ',"Sync_byte_error":', str(self.Sync_byte_error),
               ',"PAT_error":', str(self.PAT_error),
               ',"CC_errors":', str(self.CC_errors),
               ',"PMT_error":', str(self.PMT_error),
               ',"PID_error":', str(self.PID_error),
               ',"Transport_error":', str(self.Transport_error),
               ',"CRC_error":', str(self.CRC_error),
               ',"PCR_repetition_error":', str(self.PCR_repetition_error),
               ',"PCR_discontinuity_indicator_error":', str(self.PCR_discontinuity_indicator_error),
               ',"PTS_error":', str(self.PTS_error),
               ',"CAT_error":', str(self.CAT_error),
               '}']
        return ''.join(lst)

    def __repr__(self):
        return self.__str__()


class Statistics:
    def __init__(self, psize=188, pcap=False, interval_s=1, skip_cc_err_for_first_ms=100):
        self.__pcap = pcap
        self.__stat = None
        self.__stat_prev = None
        self.__stat_program_prev = None
        self.__interval = interval_s
        self.__psize = psize * 8
        self.first_pk_dt = None
        self.__last_dt = None
        self.__current_dt = None
        self.__skip_cc_err_for_ms = skip_cc_err_for_first_ms
        self.__start_timer()

        self.monitoring_start_dt = None
        self.monitoring_end_dt = None
        self.pat_received_dt = None
        self.pmt_received_dt = None
        self.cat_received_dt = None
        self.sdt_received_dt = None

        self.programs = Programs()
        self.viewer = Viewer()

        # Events
        self.onStatReady = Event()          # Fired for each stat interval
        self.onFinalStatReady = Event()     # Fired when final start is ready

    def __start_timer(self):
        self.__timer = threading.Timer(self.__interval, self.__generate_stat)
        self.__timer.start()

    def update_programs_info(self, dt: datetime, programs: Programs, pat=None, pmt=None, cat=None, sdt=None):
        self.programs = copy.deepcopy(programs)
        if pat is not None:
            self.pat_received_dt = dt
        if pmt is not None:
            self.pmt_received_dt = dt
        if cat is not None:
            self.cat_received_dt = dt
        if sdt is not None:
            self.sdt_received_dt = dt

    """def show_table_data(self, dt: datetime, programs: Programs, sdt=None, bat=None, nit=None):
        if sdt is not None:
            self.viewer.print_sdt(sdt, dt=dt)
        if bat is not None:
            self.viewer.print_bat(bat, dt=dt)"""

    def update_stat(self, dpk: TSPacket, rsync: int, pat=None, pmt=None, cat=None, crc32_ok=None, pcr_pid=False,
                    pes=None):
        if self.first_pk_dt is None:
            self.first_pk_dt = dpk.dt
        pid_stat = None
        is_new_pid = False
        index = 0
        if self.__stat is None:
            self.__stat = list()
        else:
            # Find stat object for pid
            for stat in self.__stat:
                if stat['pid'] == dpk.tsh_pid:
                    pid_stat = stat
                    break
                index += 1
        if pid_stat is None:
            pid_stat = {'pid': dpk.tsh_pid, 'stat': PidStat()}
            is_new_pid = True

        # Packet count
        pid_stat['stat'].Packet_count += 1
        if dpk.tsh_tsc != 0:
            pid_stat['stat'].Scrambled_count += 1
        # Rsync
        if rsync != 0:
            pid_stat['stat'].TS_sync_loss += 1
        # Sync byte error
        if dpk.tsh_sync != 71:
            pid_stat['stat'].Sync_byte_error += 1
        # PAT_error
        # PAT does not occur at least every 0,5 s
        # a PID 0x0000 does not contain a table_id 0x00 (i.e. a PAT)
        # Scrambling_control_field is not 00 for PID 0x0000
        if pat is not None:
            if (pid_stat['stat'].x_pam_dt is not None
                    and (pid_stat['stat'].x_pam_dt + datetime.timedelta(milliseconds=500) < dpk.dt
                         or dpk.tsh_tsc != 0 or pat.table_id != 0)):
                pid_stat['stat'].PAT_error += 1
            pid_stat['stat'].x_pam_dt = dpk.dt
        # CC check
        # Incorrect packet order
        # a packet occurs more than twice
        # lost packet
        # The continuity_counter shall not be incremented when
        # the adaptation_field_control of the packet equals '00' or '10'
        # or PID = 0x1FFF - Null Packet
        if dpk.tsh_pid != 8191 and dpk.tsh_afc not in [0, 2]:
            if pid_stat['stat'].cc is not None:
                if pid_stat['stat'].cc == dpk.tsh_cc:
                    if pid_stat['stat'].x_cc_repeated:
                        pid_stat['stat'].x_cc_repeated = False
                        # Skip CC_error for first self.__skip_cc_err_for_ms
                        if self.__skip_cc_err_for_ms is not None:
                            if(self.first_pk_dt + datetime.timedelta(milliseconds=self.__skip_cc_err_for_ms) < dpk.dt):
                                self.__skip_cc_err_for_ms = None
                                pid_stat['stat'].CC_errors += 1
                            """else:
                                print('CC_error skipped') """                                                 # Debug
                        else:
                            pid_stat['stat'].CC_errors += 1
                        #print('{} CC_error PID=0x{:04X} CC={}'.format(dpk.dt, dpk.tsh_pid, dpk.tsh_cc))    # Debug
                    else:
                        pid_stat['stat'].x_cc_repeated = True
                elif ((dpk.tsh_cc > 15
                       or (pid_stat['stat'].cc < 15 and pid_stat['stat'].cc + 1 != dpk.tsh_cc)
                       or (pid_stat['stat'].cc == 15 and dpk.tsh_cc != 0))):
                    # Skip CC_error for first self.__skip_cc_err_for_ms
                    if self.__skip_cc_err_for_ms is not None:
                        if (self.first_pk_dt + datetime.timedelta(milliseconds=self.__skip_cc_err_for_ms) < dpk.dt):
                            self.__skip_cc_err_for_ms = None
                            pid_stat['stat'].CC_errors += 1
                        """else:
                            print('CC_error skipped') """                                                      # Debug
                    else:
                        pid_stat['stat'].CC_errors += 1
                    #print('{} CC_error PID=0x{:04X} CC={}'.format(dpk.dt, dpk.tsh_pid, dpk.tsh_cc))         # Debug
            pid_stat['stat'].cc = dpk.tsh_cc
        # PMT_error
        # Sections with table_id 0x02, (i.e. a PMT), do not
        # occur at least every 0,5 s on the PID which is referred to in the PAT
        # Scrambling_control_field is not 00 for all PIDs containing sections with table_id 0x02 (i.e. a PMT)
        if pmt is not None:
            if (pid_stat['stat'].x_pmt_dt is not None
                    and (pid_stat['stat'].x_pmt_dt + datetime.timedelta(milliseconds=500) < dpk.dt
                         or dpk.tsh_tsc != 0 or pmt.table_id != 2)):
                pid_stat['stat'].PMT_error += 1
            pid_stat['stat'].x_pmt_dt = dpk.dt
        # PID_error
        # It is checked whether there exists a data stream for each PID that occurs. This error might occur
        # where TS are multiplexed, or demultiplexed and again remultiplexed.
        # The user specified period should not exceed 5 s for video or audio PIDs (see note). Data services
        # and audio services with ISO 639 [i.17] language descriptor with type greater than '0' should be
        # excluded from this 5 s limit.
        # NOTE: For PIDs carrying other information such as sub-titles, data services or audio services with
        # ISO 639 [i.17] language descriptor with type greater than '0', the time between two consecutive
        # packets of the same PID may be significantly longer.
        if pid_stat['stat'].x_pid_dt is not None and pid_stat['stat'].x_pid_dt + datetime.timedelta(seconds=5) < dpk.dt:
            pid_stat['stat'].PID_error += 1
        pid_stat['stat'].x_pid_dt = dpk.dt
        # Transport_error
        # Transport_error_indicator in the TS-Header is set to "1"
        if dpk.tsh_tei == 1:
            pid_stat['stat'].Transport_error += 1
        # CRC_error
        # CRC error occurred in CAT, PAT, PMT, NIT, EIT, BAT, SDT or TOT table
        if crc32_ok is not None and crc32_ok is False:
            pid_stat['stat'].CRC_error += 1
        # PCR errors
        if pcr_pid:
            if pid_stat['stat'].x_pcr_dt is not None:
                # PCR_discontinuity_indicator_error
                # The difference between two consecutive PCR values (PCRi+1 – PCRi) is outside the range of
                # 0...100 ms without the discontinuity_indicator set
                if pid_stat['stat'].x_pcr_dt + datetime.timedelta(milliseconds=100) < dpk.dt and dpk.af_disc != 1:
                    pid_stat['stat'].PCR_discontinuity_indicator_error += 1
                # PCR_repetition_error
                # Time interval between two consecutive PCR values more than 40 ms
                elif pid_stat['stat'].x_pcr_dt + datetime.timedelta(milliseconds=40) < dpk.dt:
                    pid_stat['stat'].PCR_repetition_error += 1
            pid_stat['stat'].x_pcr_dt = dpk.dt
        # PTS_error
        # PTS repetition period more than 700 ms
        if pes is not None:
            if (pid_stat['stat'].x_pts_dt is not None and pes.PTS is not None
                    and pid_stat['stat'].x_pts_dt + datetime.timedelta(milliseconds=700) < dpk.dt):
                pid_stat['stat'].PTS_error += 1
            pid_stat['stat'].x_pts_dt = dpk.dt
        # CAT_error
        # Packets with transport_scrambling_control not 00 present, but no section with table_id = 0x01
        # (i.e. a CAT) present
        # Section with table_id other than 0x01 (i.e. not a CAT) found on PID 0x0001
        if cat is not None and cat.table_id != 1:
            pid_stat['stat'].CAT_error += 1
        # Update stat data
        if is_new_pid:
            self.__stat.append(pid_stat)
        else:
            self.__stat[index] = pid_stat
        # Check if need generate stat (in case of parsing pcap file instead of real stream)
        self.__current_dt = dpk.dt
        if self.__last_dt is None:
            self.__last_dt = self.__current_dt
        elif self.__pcap and self.__last_dt + datetime.timedelta(seconds=self.__interval) < self.__current_dt:
            self.__timer.cancel()
            self.__generate_stat()

    def __generate_stat(self, restart_timer=True, is_final=False):
        result = None
        if self.__stat is not None:
            if self.__stat_prev is None or is_final:
                self.__stat_program_prev = PidStat()
                self.__stat_prev = list()

            # Calculate Program stat
            stat_program = PidStat()
            for pid in self.__stat:
                stat_program.Packet_count += pid['stat'].Packet_count
                stat_program.Scrambled_count += pid['stat'].Scrambled_count
                stat_program.TS_sync_loss += pid['stat'].TS_sync_loss
                stat_program.Sync_byte_error += pid['stat'].Sync_byte_error
                stat_program.PAT_error += pid['stat'].PAT_error
                stat_program.CC_errors += pid['stat'].CC_errors
                stat_program.PMT_error += pid['stat'].PMT_error
                stat_program.PID_error += pid['stat'].PID_error
                stat_program.Transport_error += pid['stat'].Transport_error
                stat_program.CRC_error += pid['stat'].CRC_error
                stat_program.PCR_repetition_error += pid['stat'].PCR_repetition_error
                stat_program.PCR_discontinuity_indicator_error += pid['stat'].PCR_discontinuity_indicator_error
                stat_program.PTS_error += pid['stat'].PTS_error
                stat_program.CAT_error += pid['stat'].CAT_error

            # Calculate delta between current and previous Program stat
            stat_program_delta = self.__calc_delta(stat_program, self.__stat_program_prev)

            # Check if any error appeared for Program
            has_errors = 0
            if (stat_program_delta.Scrambled_count != 0 or stat_program_delta.TS_sync_loss != 0
                    or stat_program_delta.Sync_byte_error != 0 or stat_program_delta.PAT_error != 0
                    or stat_program_delta.CC_errors != 0 or stat_program_delta.PMT_error != 0
                    or stat_program_delta.PID_error != 0 or stat_program_delta.Transport_error
                    or stat_program_delta.CRC_error != 0 or stat_program_delta.PCR_repetition_error != 0
                    or stat_program_delta.PCR_discontinuity_indicator_error != 0
                    or stat_program_delta.PTS_error != 0 or stat_program_delta.CAT_error != 0):
                has_errors = 1

            # Prepare stat results (program and pid bitrates)
            if is_final:
                time_delta = (self.__current_dt - self.first_pk_dt).total_seconds()
                results_list = ['{"monitoring_start_dt":"', str(self.monitoring_start_dt),
                                '","monitoring_end_dt":"', str(self.monitoring_end_dt),
                                '","first_pk_dt":"', str(self.first_pk_dt),
                                '","pat_received_dt":"', str(self.pat_received_dt),
                                '","pmt_received_dt":"', str(self.pmt_received_dt), '"']
            else:
                time_delta = (self.__current_dt - self.__last_dt).total_seconds()
                if time_delta == 0:
                    time_delta = 1
                results_list = ['{"dt":"', str(self.__current_dt), '"']
            # Add stat for program
            results_list.extend([',"has_errors":', str(has_errors), ',"program_bitrate":',
                                 self.__calc_bitrate(stat_program_delta.Packet_count, time_delta)])
            if has_errors == 1 or is_final:
                results_list.append(',"program_stat":' + str(stat_program_delta))
            # Add stat for program and per pid
            results_list.append(',"pids":[')
            pids_stat = ''
            for pid in self.__stat:
                pids_stat += ('{'+'"pid":' + str(pid['pid']) + ',"bitrate":'
                                 + self.__calc_bitrate(pid['stat'].Packet_count
                                                       - self.__find_pid_stat_prev(pid['pid']).Packet_count,
                                                       time_delta))
                if has_errors == 1 or is_final:
                    pids_stat += (',"stat":' + str(self.__calc_delta(pid['stat'],
                                                                     self.__find_pid_stat_prev(pid['pid']))))
                pids_stat += '},'
            results_list.append(pids_stat[:-1] + ']')

            results_list.append('}')
            result = ''.join(results_list)

            self.__stat_prev = copy.deepcopy(self.__stat)
            self.__stat_program_prev = copy.deepcopy(stat_program)
            self.__last_dt = self.__current_dt
        else:
            if is_final:
                results_list = ['{"monitoring_start_dt":"', str(self.monitoring_start_dt),
                                '","monitoring_end_dt":"', str(self.monitoring_end_dt),
                                '","first_pk_dt":"', str(self.first_pk_dt),
                                '","pat_received_dt":"', str(self.pat_received_dt),
                                '","pmt_received_dt":"', str(self.pmt_received_dt),
                                '","has_errors":-1}']
                result = ''.join(results_list)
            else:
                result = '{"dt":"' + str(datetime.datetime.now()) + '","has_errors":-1}'
        if restart_timer:
            self.__start_timer()
        if (not is_final) and self.onStatReady.getHandlerCount() > 0:
                self.onStatReady.fire(stat_result=result)
        return result

    def __calc_bitrate(self, packet_count: int, time_delta: float) -> str:
        return str(round(packet_count*self.__psize/time_delta))

    def __calc_delta(self, stat: PidStat, stat_prev: PidStat) -> PidStat:
        stat_delta = PidStat()
        stat_delta.Packet_count = stat.Packet_count - stat_prev.Packet_count
        stat_delta.Scrambled_count = stat.Scrambled_count - stat_prev.Scrambled_count
        stat_delta.TS_sync_loss = stat.TS_sync_loss - stat_prev.TS_sync_loss
        stat_delta.Sync_byte_error = stat.Sync_byte_error - stat_prev.Sync_byte_error
        stat_delta.PAT_error = stat.PAT_error - stat_prev.PAT_error
        stat_delta.CC_errors = stat.CC_errors - stat_prev.CC_errors
        stat_delta.PMT_error = stat.PMT_error - stat_prev.PMT_error
        stat_delta.PID_error = stat.PID_error - stat_prev.PID_error
        stat_delta.Transport_error = stat.Transport_error - stat_prev.Transport_error
        stat_delta.CRC_error = stat.CRC_error - stat_prev.CRC_error
        stat_delta.PCR_repetition_error = (stat.PCR_repetition_error - stat_prev.PCR_repetition_error)
        stat_delta.PCR_discontinuity_indicator_error = (stat.PCR_discontinuity_indicator_error
                                                                - stat_prev.PCR_discontinuity_indicator_error)
        stat_delta.PTS_error = stat.PTS_error - stat_prev.PTS_error
        stat_delta.CAT_error = stat.CAT_error - stat_prev.CAT_error
        return stat_delta

    def __find_pid_stat_prev(self, pid: int) -> PidStat:
        for pid_prev in self.__stat_prev:
            if pid == pid_prev['pid']:
                return pid_prev['stat']
        return PidStat()

    def get_stat(self) -> dict:
        self.__timer.cancel()
        self.__generate_stat(restart_timer=False)
        stat = self.__generate_stat(restart_timer=False, is_final=True)
        if self.onFinalStatReady.getHandlerCount() > 0:
            self.onFinalStatReady.fire(stat_result=stat)

        return json.loads(stat)
