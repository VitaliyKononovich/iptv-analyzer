from ts.ts_parser import TSParser
from models import *
import datetime
import logging
from events.event import Event


class TSReader:
    """ Class for reading TS packets stream"""
    def __init__(self):
        """
        Initialize object

        :param statistics: Statistics calss object (if statistic needed)
        """
        self.__ts_parser = TSParser()
        self.__programs = Programs.Programs()

        # Events
        self.onPacketDecoded = Event()          # Fired for each decoded packet to collect statistic
        self.onPatReceived = Event()            # Fired when PAT received or updated
        self.onPmtReceived = Event()            # Fired when PMT received or updated
        self.onCatReceived = Event()            # Fired when CAT received or updated
        self.onProgramSdtReceived = Event()     # Fired when SDT related to Program ID received or updated
        self.onSdtReceived = Event()            # Fired when any SDT received
        self.onBatReceived = Event()            # Fired when any BAT received
        self.onNitReceived = Event()            # Will be fired when NIT received or updated

        self.known_pids = set()
        self.known_pids.add(0)      # 0x0000 - Program Association Table (PAT)
        self.known_pids.add(1)      # 0x0001 - Conditional Access Table (CAT)
        self.known_pids.add(2)      # 0x0002 - Transport Stream Description Table (TSDT)
        self.known_pids.add(3)      # 0x0003 - IPMP Control Information Table
        self.known_pids.add(16)     # 0x0010 - NIT, ST
        self.known_pids.add(17)     # 0x0011 - SDT, BAT, ST
        self.known_pids.add(18)     # 0x0012 - EIT, ST, CIT
        self.known_pids.add(19)     # 0x0013 - RST, ST
        self.known_pids.add(20)     # 0x0014 - TDT, TOT, ST
        self.known_pids.add(21)     # 0x0015 - network synchronization
        self.known_pids.add(22)     # 0x0016 -  RNT
        self.known_pids.add(28)     # 0x001C - inband signalling
        self.known_pids.add(29)     # 0x001D - measurement
        self.known_pids.add(30)     # 0x001E - DIT
        self.known_pids.add(31)     # 0x001F - SIT
        self.known_pids.add(8187)   # 0x1FFB - Used by DigiCipher 2/ATSC MGT metadata
        self.known_pids.add(8191)   # 0x1FFF - Null Packet

        self.__pid_17_buffer = None

    def get_programs_data(self) -> Programs.Programs:
        return self.__programs

    def read(self, data: bytes, dt: datetime, parse_ts=True):
        """
        Read clean TS stream packets (without IP/UDP layer) and prepare statistics

        :param data: Clean TS stream packet (may include several TS packets inside)
        :param dt: Date and time when TS stream packet arrived
        :param parse_ts: If True (by default) method parse TS header for each TS packet
        """
        for pk, dpk, rsync in self.__ts_parser.parse(data, parse_ts):
            # print('\t' + str(dpk))
            if dpk is not None:
                dpk.dt = dt
                if dpk.tsh_pid == 0:
                    # 0x0000 - Program Association Table (PAT)
                    pat = self.__ts_parser.decode_pat(pk[dpk.payload:])
                    if self.__programs.pat is None:
                        self.__programs.pat = pat
                        if self.onPatReceived.getHandlerCount() > 0:
                            self.onPatReceived.fire(dt=dt, programs=self.__programs, pat=pat)
                    elif pat.crc32 != self.__programs.pat.crc32 and pat.crc32_ok:
                        # Check what is really updated
                        warn_str = '{}: PAT updated'
                        warn_lst = [dt]
                        if self.__programs.pat.table_id != pat.table_id:
                            warn_str += ': table_id {} -> {}'
                            warn_lst.extend([pat.table_id, self.__programs.pat.table_id])
                        if self.__programs.pat.ts_id != pat.ts_id:
                            warn_str += ': ts_id {} -> {}'
                            warn_lst.extend([pat.ts_id, self.__programs.pat.ts_id])
                        if self.__programs.pat.ver_num != pat.ver_num:
                            warn_str += ': ver_num {} -> {}'
                            warn_lst.extend([pat.ver_num, self.__programs.pat.ver_num])
                        set_pat_old = set(tuple(sorted(d.items())) for d in self.__programs.pat.prog_nums)
                        set_pat_new = set(tuple(sorted(d.items())) for d in pat.prog_nums)
                        set_difference = set_pat_old.symmetric_difference(set_pat_new)
                        if len(set_difference) > 0:
                            warn_str += ': prog_nums differences are {}'
                            warn_lst.append(set_difference)
                        self.__programs.update_pat(pat)
                        logging.warning(warn_str.format(*warn_lst))
                        if self.onPatReceived.getHandlerCount() > 0:
                            self.onPatReceived.fire(dt=dt, programs=self.__programs, pat=pat)
                    if self.onPacketDecoded.getHandlerCount() > 0:
                        self.onPacketDecoded.fire(dpk, rsync, pat=pat, crc32_ok=pat.crc32_ok)
                elif dpk.tsh_pid == 1:
                    # 0x0001 - Conditional Access Table (CAT)
                    cat = self.__ts_parser.decode_cat(pk[dpk.payload:])
                    if self.__programs.cat is None:
                        self.__programs.cat = cat
                        if self.onCatReceived.getHandlerCount() > 0:
                            self.onCatReceived.fire(dt=dt, programs=self.__programs, cat=cat)
                    elif cat.crc32 != self.__programs.cat.crc32:
                        logging.warning('{}: CAT updated'.format(dt))
                        if self.onCatReceived.getHandlerCount() > 0:
                            self.onCatReceived.fire(dt=dt, programs=self.__programs, cat=cat)
                    if self.onPacketDecoded.getHandlerCount() > 0:
                        self.onPacketDecoded.fire(dpk, rsync, cat=cat, crc32_ok=cat.crc32_ok)
                elif dpk.tsh_pid == 17:
                    # 0x0011 - SDT, BAT, ST
                    # print(dpk.dt)
                    parse_SDT = False
                    # Parse SDT only if we need Programs SDT or information about each SDT received
                    # Parse BAT only if we need information about each BAT received
                    if self.onProgramSdtReceived.getHandlerCount() > 0 and self.__programs.sdt is None:
                        if self.__programs.sdt is None:
                            parse_SDT = True
                    if self.onSdtReceived.getHandlerCount() > 0:
                        parse_SDT = True
                    res = self.__ts_parser.decode_pid_17(pk[dpk.payload:],
                                     parse_SDT=parse_SDT,
                                     parse_BAT=(True if self.onBatReceived.getHandlerCount() > 0 else False))
                    # Analyzing SDT
                    if res['sdt'] is not None:
                        if (self.onProgramSdtReceived.getHandlerCount() > 0 and self.__programs.sdt is None
                                and self.__programs.pat is not None):
                            for service in res['sdt'].services:
                                if service['service_id'] in [program['program_number'] for program in self.__programs.pat.prog_nums]:
                                    for descriptor in service['descriptors']:
                                        if descriptor['descriptor_tag'] == 72:  # service_descriptor
                                            sdt = res['sdt']
                                            sdt.services = [service]
                                            self.__programs.sdt = sdt
                                            self.onProgramSdtReceived.fire(dt=dt, programs=self.__programs, sdt=sdt)
                                            break
                        if self.onSdtReceived.getHandlerCount() > 0:
                            self.onSdtReceived.fire(dt=dt, programs=self.__programs, sdt=res['sdt'])
                    # Analyzing BAT
                    elif (True if self.onBatReceived.getHandlerCount() > 0 else False) and res['bat'] is not None:
                        if self.onBatReceived.getHandlerCount() > 0:
                            self.onBatReceived.fire(dt=dt, programs=self.__programs, bat=res['bat'])
                    if self.onPacketDecoded.getHandlerCount() > 0:
                        crc32_ok = None
                        if res['sdt'] is not None:
                            crc32_ok = res['sdt'].crc32_ok
                        elif res['bat'] is not None:
                            crc32_ok = res['bat'].crc32_ok
                        self.onPacketDecoded.fire(dpk, rsync, crc32_ok=crc32_ok)
                elif dpk.tsh_pid in self.__programs.get_pmt_pids():
                    # Program Map Table
                    pmt = self.__ts_parser.decode_pmt(pk[dpk.payload:])
                    if pmt is not None:
                        if self.__programs.get_prog_pmt(dpk.tsh_pid) is None:
                            self.__programs.set_prog_pmt(dpk.tsh_pid, pmt)
                            if self.onPmtReceived.getHandlerCount() > 0:
                                self.onPmtReceived.fire(dt=dt, programs=self.__programs, pmt=pmt)
                        elif pmt.crc32 != self.__programs.get_prog_pmt(dpk.tsh_pid).crc32 and pmt.crc32_ok:
                            # Check what is really updated
                            pmt_old = self.__programs.get_prog_pmt(dpk.tsh_pid)
                            warn_str = '{}: PMT updated'
                            warn_lst = [dt]
                            if pmt_old.table_id != pmt.table_id:
                                warn_str += ': table_id {} -> {}'
                                warn_lst.extend([pmt.table_id, pmt_old.table_id])
                            if pmt_old.prog_num != pmt.prog_num:
                                warn_str += ': prog_num {} -> {}'
                                warn_lst.extend([pmt.prog_num, pmt_old.prog_num])
                            if pmt_old.pcr_pid != pmt.pcr_pid:
                                warn_str += ': pcr_pid {} -> {}'
                                warn_lst.extend([pmt.pcr_pid, pmt_old.pcr_pid])
                            if pmt_old.ver_num != pmt.ver_num:
                                warn_str += ': ver_num {} -> {}'
                                warn_lst.extend([pmt.ver_num, pmt_old.ver_num])
                            set_pmt_old = set(tuple(sorted(d.items())) for d in pmt_old.streams)
                            set_pmt_new = set(tuple(sorted(d.items())) for d in pmt.streams)
                            set_difference = set_pmt_old.symmetric_difference(set_pmt_new)
                            if len(set_difference) > 0:
                                warn_str += ': streams differences are {}'
                                warn_lst.append(set_difference)
                            self.__programs.update_prog_pmt(dpk.tsh_pid, pmt)
                            logging.warning(warn_str.format(*warn_lst))
                            if self.onPmtReceived.getHandlerCount() > 0:
                                self.onPmtReceived.fire(dt=dt, programs=self.__programs, pmt=pmt)
                    if self.onPacketDecoded.getHandlerCount() > 0:
                        self.onPacketDecoded.fire(dpk, rsync, pmt=pmt, crc32_ok=pmt.crc32_ok)
                elif dpk.tsh_pid in self.__programs.get_net_pids():
                    # Network Information Table
                    logging.warning('NIT - no decoder')
                    if self.onPacketDecoded.getHandlerCount() > 0:
                        self.onPacketDecoded.fire(dpk, rsync)
                elif dpk.tsh_pid in self.__programs.get_stream_pids():
                    # Program main streams
                    pes = None
                    if dpk.tsh_afc in [1, 3]:   # payload
                        p = pk[dpk.payload:dpk.payload+3]
                        if p == b'\x00\x00\x01' and pk[dpk.payload+3] >= 188:   # stream_id >= 188
                            # Packetized Elementary Stream (PES)
                            pes = self.__ts_parser.decode_pes(pk[dpk.payload+3:])
                            #if pes.PTS_DTS_flags in [2, 3]:
                            #    print('{} - PID=0x{:04X} stream_type={} PTS={}'.format(dpk.dt, dpk.tsh_pid, pes.stream_type, pes.PTS/90000))
                    if self.onPacketDecoded.getHandlerCount() > 0:
                        self.onPacketDecoded.fire(dpk, rsync, pes=pes, pcr_pid=(True if dpk.tsh_pid in self.__programs.get_pcr_pids() else False))
                elif dpk.tsh_pid in self.__programs.get_other_pids():
                    # Program other streams
                    if self.onPacketDecoded.getHandlerCount() > 0:
                        self.onPacketDecoded.fire(dpk, rsync, pcr_pid=(True if dpk.tsh_pid in self.__programs.get_pcr_pids() else False))
                elif dpk.tsh_pid in self.known_pids and dpk.tsh_pid != 8191:   # 0x1FFF - Null Packet
                    # Known PIDs
                    logging.warning('Known PID: 0x{:04X} - no decoder'.format(dpk.tsh_pid))
                    if self.onPacketDecoded.getHandlerCount() > 0:
                        self.onPacketDecoded.fire(dpk, rsync)
                else:
                    if self.onPacketDecoded.getHandlerCount() > 0:
                        self.onPacketDecoded.fire(dpk, rsync)
