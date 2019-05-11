import struct
from models import *
import logging


class DescriptorParser:
    @staticmethod
    def decode_descriptors(pk: bytes) -> list:
        pos = 0
        pos2 = len(pk)
        descriptors = list()
        while pos < pos2:
            descriptor_tag, descriptor_length = struct.unpack('>BB', pk[pos:pos+2])
            pos += 2
            if descriptor_tag == 9:  # CA_descriptor
                ca_system_id, ca_pid = struct.unpack('>HH', pk[pos:pos+4])
                ca_pid = ca_pid & 8191
                descriptors.append({'descriptor_tag': descriptor_tag,
                                    'descriptor_data': {'ca_system_id': ca_system_id, 'ca_pid': ca_pid,
                                             'private_data': pk[pos+4:pos+descriptor_length]}})
                pos += descriptor_length
            elif descriptor_tag == 65:  # service_list_descriptor
                service_list = list()
                pos3 = pos + descriptor_length
                while pos < pos3:
                    service_id, service_type = struct.unpack('>HB', pk[pos:pos+3])
                    pos += 3
                    service_list.append({'service_id': service_id, 'service_type': service_type})
                descriptors.append({'descriptor_tag': descriptor_tag,
                                    'descriptor_data': {'service_list': service_list}})
            elif descriptor_tag == 71:  # bouquet_name_descriptor
                descriptors.append({'descriptor_tag': descriptor_tag,
                                    'descriptor_data': {'bouquet_name': DescriptorParser.decode_text(pk[pos:pos+descriptor_length])}})
            elif descriptor_tag == 72:  # service_descriptor
                service_type, length = struct.unpack('>BB', pk[pos:pos+2])
                if length > 0:
                    service_provider_name = DescriptorParser.decode_text(pk[pos+2:pos+2+length])
                else:
                    service_provider_name = None
                pos += 2 + length
                length = pk[pos]
                if length > 0:
                    service_name = DescriptorParser.decode_text(pk[pos+1:pos+1+length])
                else:
                    service_name = None
                pos += 1 + length
                descriptors.append({'descriptor_tag': descriptor_tag, 'descriptor_data': {'service_type': service_type,
                                    'service_provider_name': service_provider_name, 'service_name': service_name}})
            elif descriptor_tag == 83:  # CA_identifier_descriptor
                ca_system_id = list()
                pos3 = pos + descriptor_length
                while pos < pos3:
                    ca_system_id.append(struct.unpack('>H', pk[pos:pos + 2])[0])
                    pos += 2
                descriptors.append({'descriptor_tag': descriptor_tag,
                                    'descriptor_data': {'ca_system_id': ca_system_id}})
            else:
                descriptors.append({'descriptor_tag': descriptor_tag, 'descriptor_data': pk[pos:pos+descriptor_length]})
                pos += descriptor_length
        return descriptors

    @staticmethod
    def decode_text(pk: bytes):
        if pk[0] in range(1, 11):
            return pk[1:].decode('iso-8859-'+str(pk[0]+4))
        else:
            return pk


class TSParser:
    """ Class for parsing TS packets """
    def __init__(self, psize=188):
        """
        Initialize the object

        :param psize: TS packet size. Default is 188 bytes
        """
        self.__psize = psize
        self.__resync = 0
        self.__pid_17_buffer = None
        self.__pmt_buffer = None

    def parse(self, data: bytes, parse_ts=True) -> tuple:
        """
        Find the TS packets in bytes array and parse TS header if parse_ts=True. Returns each found TS packet one by one

        :param data: Bytes array to be parsed
        :param parse_ts: If True (by default) method parse TS header for each TS packet
        :return: Return tuple wich includes: packet - original ts packet bytes, parsed - parsed TS header corresponding
                to this TS packet as TSPacket object and resync - bytes offest if for TS packet resync takes place
        """
        sync_offset = data.find(b'\x47')
        if sync_offset == -1:  # No sync bit in packet
            return None, None, len(data)
        if sync_offset != 0:  # Resync
            data = data[sync_offset:]
        for i in range(int(len(data) / self.__psize)):
            if sync_offset != 0:
                self.__resync = sync_offset
                sync_offset = 0
            else:
                self.__resync = 0
            packet = data[:self.__psize]
            data = data[self.__psize:]
            if len(packet) < self.__psize:
                yield None, None, len(packet)
            parsed = None
            if parse_ts:
                parsed = self.__parse(packet)
            yield packet, parsed, self.__resync

    def __parse(self, packet: bytes) -> TSPacket.TSPacket:
        """
        Parse TS packet header and adaptation fields

        :param packet: TS packet bytes array
        :return: return parsed object TSPacket
        """
        p = TSPacket.TSPacket()
        try:
            b1, b23, b4 = struct.unpack('>BHB', packet[0:4])
            # 4-byte Transport Stream Header
            p.tsh_sync = b1
            p.tsh_tei = (b23 & 32768) >> 15
            p.tsh_pusi = (b23 & 16384) >> 14
            p.tsh_tp = (b23 & 8192) >> 13
            p.tsh_pid = b23 & 8191
            p.tsh_tsc = (b4 & 192) >> 6
            p.tsh_afc = (b4 & 48) >> 4
            p.tsh_cc = b4 & 15
            # Adaptation Field
            if p.tsh_afc == 2 or p.tsh_afc == 3:
                p.af_length = packet[4]  # b1
                if p.af_length != 0:
                    b2 = packet[5]
                    p.af_disc = (b2 & 128) >> 7
                    p.af_random = (b2 & 64) >> 6
                    p.af_espi = (b2 & 32) >> 5
                    p.af_pcrf = (b2 & 16) >> 4
                    p.af_opcrf = (b2 & 8) >> 3
                    p.af_spf = (b2 & 4) >> 2
                    p.af_tpdf = (b2 & 2) >> 1
                    p.af_afef = b2 & 1
                    pos = 6
                    if p.af_pcrf:
                        # p.af_pcr = packet[6:12]
                        b14, b56 = struct.unpack('>LH', packet[6:12])
                        p.af_pcr = ((b14 << 1) + (b56 >> 15)) * 300 + (b56 & 511)
                        pos += 6
                    if p.af_opcrf:
                        # p.af_opcr = packet[pos:(pos+6)]
                        b14, b56 = struct.unpack('>LH', packet[6:12])
                        p.af_opcr = ((b14 << 1) + (b56 >> 15)) * 300 + (b56 & 511)
                        pos += 6
                    if p.af_spf:
                        p.af_sc = packet[pos]
                        pos += 1
                    if p.af_tpdf:
                        l = packet[pos]
                        pos += 1
                        p.af_tpd = packet[pos:(pos+l)]
                        pos += l
                    if p.af_afef:
                        l = packet[pos]
                        pos += 1
                        p.af_ae = packet[pos:(pos+l)]
            # Calculate payload start byte
            if p.tsh_afc == 1:
                p.payload = 4
            elif p.tsh_afc == 3:
                p.payload = 5 + p.af_length
            return p
        except Exception as err:
            logging.warning('TS packet parsing error:' + str(err))
            return None

    def decode_pat(self, pat: bytes) -> PAT.PAT:
        """
        Decode Program Association Table (PAT)

        :param pat: PAT packet bytes
        :return: return decoded PAT object
        """
        patdk = PAT.PAT()
        try:
            pointer_field = pat[0]
            pos = 1 + pointer_field
            patdk.table_id = pat[pos]
            b12, patdk.ts_id = struct.unpack('>HH', pat[pos+1:pos+5])
            section_length = b12 & 4095
            b = pat[pos+5]
            patdk.ver_num = (b & 62) >> 1
            patdk.cur_next_ind = b & 1
            patdk.sec_num = pat[pos+6]
            patdk.last_sec_num = pat[pos+7]
            pos += 8
            for i in range(int((section_length-9)/2)-1):
                program_number, b34 = struct.unpack('>HH', pat[pos:pos+4])
                p = b34 & 8191
                if program_number == 0:
                    patdk.prog_nums.append({'program_number': program_number, 'network_PID': p, 'program_map_PID': None})
                else:
                    patdk.prog_nums.append({'program_number': program_number, 'network_PID': None, 'program_map_PID': p})
                pos += 4
            try:
                patdk.crc32 = (struct.unpack('>L', pat[pos:pos+4]))[0]
                crc_check = self.crc32mpeg2(pat[1+pointer_field:pos])
                if patdk.crc32 != crc_check:
                    patdk.crc32_ok = False
            except Exception as err:
                patdk.crc32_ok = False
                logging.warning('CAT CRC check error:' + str(err))
            return patdk
        except Exception as err:
            logging.warning('PAT parsing error:' + str(err))
            return None

    def decode_pmt(self, pmt: bytes) -> PMT.PMT:
        """
        Decode Program Map Table (PMT)

        :param pmt: PMT packet bytes
        :return: return decoded PMT object
        """
        pmtdk = None
        try:
            if self.__pmt_buffer is None:
                p = pmt[0]
                table_id, b12 = struct.unpack('>BH', pmt[1 + p:4 + p])
                section_length = b12 & 4095
                if section_length > (len(pmt)-3-p):
                    self.__pmt_buffer = {'section_length': section_length, 'buffer': pmt}
                else:
                    pmtdk = self._decode_pmt(pmt)
            else:
                if self.__pmt_buffer['section_length'] > (len(self.__pmt_buffer['buffer']) + len(pmt)):
                    self.__pmt_buffer['buffer'] += pmt
                else:
                    self.__pmt_buffer['buffer'] += pmt
                    pmtdk = self._decode_pmt(self.__pmt_buffer['buffer'])
                    self.__pmt_buffer = None
        except Exception as err:
            logging.warning('PMT parsing error:' + str(err))
        return pmtdk

    def _decode_pmt(self, pmt: bytes) -> PMT.PMT:
        """
        Internal method for Decode Program Map Table (PMT)

        :param pmt: PMT packet bytes
        :return: return decoded PMT object
        """
        pmtdk = PMT.PMT()
        try:
            pointer_field = pmt[0]
            pos = 1 + pointer_field
            pmtdk.table_id = pmt[pos]
            b12, pmtdk.prog_num = struct.unpack('>HH', pmt[pos+1:pos+5])
            section_length = b12 & 4095
            pos_crc = pos + 3 + section_length - 4  # - CRC
            b = pmt[pos + 5]
            pmtdk.ver_num = (b & 62) >> 1
            pmtdk.cur_next_ind = b & 1
            pmtdk.sec_num = pmt[pos + 6]
            pmtdk.last_sec_num = pmt[pos + 7]
            pmtdk.pcr_pid = struct.unpack('>H', pmt[pos+8:pos+10])[0] & 8191
            prog_info_length = struct.unpack('>H', pmt[pos + 10:pos + 12])[0] & 4095
            #pos += 12 + prog_info_length  # skip descriptor
            pos += 12
            if prog_info_length > 0:
                pmtdk.descriptors = DescriptorParser.decode_descriptors(pmt[pos:pos+prog_info_length])
            pos += prog_info_length
            while pos < pos_crc:
                stream_type, elementary_pid, es_info_length = struct.unpack('>BHH', pmt[pos:pos+5])
                elementary_pid = elementary_pid & 8191
                es_info_length = es_info_length & 4095
                pmtdk.streams.append({'stream_type': stream_type, 'elementary_pid': elementary_pid})
                pos += 5 + es_info_length  # skip descriptor
            try:
                pmtdk.crc32 = (struct.unpack('>L', pmt[pos_crc:pos_crc + 4]))[0]
                crc_check = self.crc32mpeg2(pmt[1+pointer_field:pos_crc])
                if pmtdk.crc32 != crc_check:
                    pmtdk.crc32_ok = False
            except Exception as err:
                pmtdk.crc32_ok = False
                logging.warning('PMT CRC check error:' + str(err))
            return pmtdk
        except Exception as err:
            logging.warning('PMT parsing error:' + str(err))
            return None

    def decode_cat(self, cat: bytes) -> CAT.CAT:
        """
        Decode Conditional Access Table (CAT)

        :param cat: CAT packet bytes
        :return: return decoded CAT object
        """
        catdk = CAT.CAT()
        try:
            pointer_field = cat[0]
            pos = 1 + pointer_field
            catdk.table_id = cat[pos]
            b12 = struct.unpack('>H', cat[pos+1:pos+3])[0]
            section_length = b12 & 4095
            pos_crc = pos + 3 + section_length - 4  # - CRC
            b = cat[pos+5]   # skip 2 bytes from reserved
            catdk.ver_num = (b & 62) >> 1
            catdk.cur_next_ind = b & 1
            catdk.sec_num = cat[pos+6]
            catdk.last_sec_num = cat[pos+7]
            pos += 8
            if pos < pos_crc:
                catdk.descriptors = DescriptorParser.decode_descriptors(cat[pos:pos_crc])
            try:
                catdk.crc32 = (struct.unpack('>L', cat[pos_crc:pos_crc + 4]))[0]
                crc_check = self.crc32mpeg2(cat[1+pointer_field:pos_crc])
                if catdk.crc32 != crc_check:
                    catdk.crc32_ok = False
            except Exception as err:
                catdk.crc32_ok = False
                logging.warning('CAT CRC check error:' + str(err))
            return catdk
        except Exception as err:
            logging.warning('CAT parsing error:' + str(err))
            return None

    def decode_pid_17(self, pk: bytes, parse_SDT=False, parse_BAT=False) -> dict:
        """
        Decode data sent in pid 17. Assumed that it is Service Description Table (SDT)
        or Bouquet Association Table (BAT)

        :param pk: packet payload bytes
        :param parse_SDT: If it is needed to decode other_transport_stream. Default: False
        :param parse_BAT: If it is needed to decode BAT. Default: False
        :return: dictionary contains SDT or BAT object if it was successfully decoded
        """
        sdt = None
        bat = None
        try:
            if self.__pid_17_buffer is None:
                p = pk[0]
                table_id, b12 = struct.unpack('>BH', pk[1+p:4+p])
                section_length = b12 & 4095
                if section_length > (len(pk)-3-p):
                    self.__pid_17_buffer = {'section_length': section_length, 'buffer': pk}
                else:
                    if table_id == 66:          # SDT - actual_transport_stream
                        sdt = self._decode_sdt(pk)
                    elif table_id == 70:        # SDT - other_transport_stream
                        if parse_SDT:
                            sdt = self._decode_sdt(pk)
                        else:
                            sdt = SDT.SDT()
                            sdt.crc32_ok = self._check_crc32_only(pk)
                    elif table_id == 74:        # BAT
                        if parse_BAT:
                            bat = self._decode_bat(pk)
                        else:
                            bat = BAT.BAT()
                            bat.crc32_ok = self._check_crc32_only(pk)
            else:
                if self.__pid_17_buffer['section_length'] > (len(self.__pid_17_buffer['buffer']) + len(pk)):
                    self.__pid_17_buffer['buffer'] += pk
                else:
                    self.__pid_17_buffer['buffer'] += pk
                    p = self.__pid_17_buffer['buffer'][0]
                    table_id = self.__pid_17_buffer['buffer'][1+p]
                    if table_id == 66:          # SDT - actual_transport_stream
                        sdt = self._decode_sdt(self.__pid_17_buffer['buffer'])
                    elif table_id == 70:        # SDT - other_transport_stream
                        if parse_SDT:
                            sdt = self._decode_sdt(self.__pid_17_buffer['buffer'])
                        else:
                            sdt = SDT.SDT()
                            sdt.crc32_ok = self._check_crc32_only(self.__pid_17_buffer['buffer'])
                    elif table_id == 74:        # BAT
                        if parse_BAT:
                            bat = self._decode_bat(self.__pid_17_buffer['buffer'])
                        else:
                            bat = BAT.BAT()
                            bat.crc32_ok = self._check_crc32_only(self.__pid_17_buffer['buffer'])
                    self.__pid_17_buffer = None
        except Exception as err:
            logging.warning('PID 17 parsing error:' + str(err))
        return {'sdt': sdt, 'bat': bat}

    def _decode_sdt(self, sdt: bytes) -> SDT.SDT:
        """
        Decode Service Description Table (SDT)

        :param sdt: SDT packet bytes
        :return: return decoded SDT object
        """
        sdtdk = SDT.SDT()
        try:
            pointer_field = sdt[0]
            pos = 1 + pointer_field
            sdtdk.table_id = sdt[pos]
            b12, sdtdk.transport_stream_id = struct.unpack('>HH', sdt[pos+1:pos+5])
            section_length = b12 & 4095
            pos_crc = pos + 3 + section_length - 4  # - CRC
            b = sdt[pos + 5]
            sdtdk.ver_num = (b & 62) >> 1
            sdtdk.cur_next_ind = b & 1
            sdtdk.sec_num, sdtdk.last_sec_num, sdtdk.original_network_id = struct.unpack('>BBH', sdt[pos+6:pos+10])
            pos += 10 + 1                           # 1 - reserved
            while pos < pos_crc:
                service_id, b34, b56 = struct.unpack('>HBH', sdt[pos:pos+5])
                EIT_schedule_flag = (b34 & 2) >> 1
                EIT_present_following_flag = b34 & 1
                running_status = (b56 & 57344) >> 13
                free_CA_mode = (b56 & 4096) >> 12
                descriptors_loop_length = (b56 & 4095)
                pos += 5
                descriptors = []
                if descriptors_loop_length > 0:
                    descriptors = DescriptorParser.decode_descriptors(sdt[pos:pos+descriptors_loop_length])
                    pos += descriptors_loop_length
                sdtdk.services.append({'service_id': service_id, 'EIT_schedule_flag': EIT_schedule_flag,
                                       'EIT_present_following_flag': EIT_present_following_flag,
                                       'running_status': running_status, 'free_CA_mode': free_CA_mode,
                                       'descriptors': descriptors})
            try:
                sdtdk.crc32 = (struct.unpack('>L', sdt[pos_crc:pos_crc+4]))[0]
                crc_check = self.crc32mpeg2(sdt[1+pointer_field:pos_crc])
                if sdtdk.crc32 != crc_check:
                    sdtdk.crc32_ok = False
            except Exception as err:
                sdtdk.crc32_ok = False
                logging.warning('SDT CRC check error:' + str(err))
            return sdtdk
        except Exception as err:
            logging.warning('SDT parsing error:' + str(err))
            return None

    def _decode_bat(self, bat: bytes) -> BAT.BAT:
        batdk = BAT.BAT()
        try:
            pointer_field = bat[0]
            pos = 1 + pointer_field
            batdk.table_id = bat[pos]
            b12, batdk.bouquet_id = struct.unpack('>HH', bat[pos+1:pos+5])
            section_length = b12 & 4095
            pos_crc = pos + 3 + section_length - 4  # - CRC
            b = bat[pos + 5]
            batdk.ver_num = (b & 62) >> 1
            batdk.cur_next_ind = b & 1
            batdk.sec_num, batdk.last_sec_num, b12 = struct.unpack('>BBH', bat[pos+6:pos+10])
            descriptors_length = b12 & 4095
            pos += 10
            if descriptors_length > 0:
                batdk.descriptors = DescriptorParser.decode_descriptors(bat[pos:pos + descriptors_length])
                pos += descriptors_length
            b12 = struct.unpack('>H', bat[pos:pos+2])[0]
            pos += 2
            transport_stream_loop_length = (b12 & 4095) + pos
            while pos < transport_stream_loop_length:
                transport_stream_id, original_network_id, b12 = struct.unpack('>HHH', bat[pos:pos+6])
                descriptors_loop_length = (b12 & 4095)
                pos += 6
                descriptors = []
                if descriptors_loop_length > 0:
                    descriptors = DescriptorParser.decode_descriptors(bat[pos:pos+descriptors_loop_length])
                    pos += descriptors_loop_length
                batdk.transport_streams.append({'transport_stream_id': transport_stream_id,
                                                'original_network_id': original_network_id, 'descriptors': descriptors})
            try:
                batdk.crc32 = (struct.unpack('>L', bat[pos_crc:pos_crc+4]))[0]
                crc_check = self.crc32mpeg2(bat[1+pointer_field:pos_crc])
                if batdk.crc32 != crc_check:
                    batdk.crc32_ok = False
            except Exception as err:
                batdk.crc32_ok = False
                logging.warning('BAT CRC check error:' + str(err))
            return batdk
        except Exception as err:
            logging.warning('BAT parsing error:' + str(err))
            return None

    def _check_crc32_only(self, pk: bytes) -> bool:
        crc32_ok = False
        try:
            pointer_field = pk[0]
            pos = 1 + pointer_field
            section_length = (struct.unpack('>H', pk[pos + 1:pos + 3])[0]) & 4095
            pos_crc = pos + 3 + section_length - 4  # - CRC
            crc32 = (struct.unpack('>L', pk[pos_crc:pos_crc + 4]))[0]
            crc_check = self.crc32mpeg2(pk[1 + pointer_field:pos_crc])
            if crc32 == crc_check:
                crc32_ok = True
        except Exception as err:
            logging.warning('CRC check error:' + str(err))
        return crc32_ok

    def decode_pes(self, pes: bytes)-> PES.PES:
        """
        Decode Packetized Elementary Stream (PES)

        :param pes: PES packet bytes
        :return: return decoded PES object
        """
        pesdk = PES.PES()
        try:
            pesdk.stream_id, PES_packet_length = struct.unpack('>BH', pes[0:3])
            if pesdk.stream_id not in [33, 188, 190, 191, 240, 241, 242, 248, 255]:
                #  33 (0x21) - unknown ?????
                # 188 (0xBC) - program_stream_map
                # 190 (0xBE) - padding_stream
                # 191 (0xBF) - private_stream_2
                # 240 (0xF0) - ECM
                # 241 (0xF1) - EMM
                # 242 (0xF2) - DSMCC_stream
                # 248 (0xF8) - ITU-T Rec. H.222.1 type E stream
                # 255 (0xFF) - program_stream_directory
                if pesdk.stream_id >> 4 == 14:
                    pesdk.stream_type = 'video-stream'
                    pesdk.stream_number = (pesdk.stream_id & 15)
                elif pesdk.stream_id >> 5 == 6:
                    pesdk.stream_type = 'audio-stream'
                    pesdk.stream_number = (pesdk.stream_id & 31)
                b1, b2, PES_header_data_length = struct.unpack('>BBB', pes[3:6])
                pesdk.PES_scrambling_control = (b1 & 16) >> 4
                # PES_priority = bool((b1 & 8) >> 3)
                # data_alignment_indicator = bool((b1 & 4) >> 2)
                pesdk.copyright = bool((b1 & 2) >> 1)
                pesdk.original_or_copy = bool(b1 & 1)
                pesdk.PTS_DTS_flags = (b2 & 192) >> 6
                pesdk.ESCR_flag = bool((b2 & 32) >> 5)
                pesdk.ES_rate_flag = bool((b2 & 16) >> 4)
                pesdk.DSM_trick_mode_flag = bool((b2 & 8) >> 3)
                pesdk.additional_copy_info_flag = bool((b2 & 4) >> 2)
                pesdk.PES_CRC_flag = bool((b2 & 2) >> 1)
                pesdk.PES_extension_flag = bool(b2 & 1)
                pos = 6
                if pesdk.PTS_DTS_flags in [2, 3]:
                    b1, b23, b45 = struct.unpack('>BHH', pes[pos:pos+5])
                    pesdk.PTS = (((b1 & 14) << 29) + ((b23 >> 1) << 15) + (b45 >> 1))
                    pos += 5
                if pesdk.PTS_DTS_flags == 3:
                    b1, b23, b45 = struct.unpack('>BHH', pes[pos:pos + 5])
                    pesdk.DTS = (((b1 & 14) << 29) + ((b23 >> 1) << 15) + (b45 >> 1))
                    pos += 5
            elif pesdk.stream_id == 190:
                # 190 (0xBE) - padding_stream
                pass
            else:
                #  33 (0x21) - unknown ?????
                # 188 (0xBC) - program_stream_map
                # 191 (0xBF) - private_stream_2
                # 240 (0xF0) - ECM
                # 241 (0xF1) - EMM
                # 242 (0xF2) - DSMCC_stream
                # 248 (0xF8) - ITU-T Rec. H.222.1 type E stream
                # 255 (0xFF) - program_stream_directory
                pass
            return pesdk
        except Exception as err:
            logging.warning('PES parsing error:' + str(err))
            return None

    def crc32mpeg2(self, data: bytes) -> int:
        """
        Calculate CRC-32/MPEG-2

        :param data: bytes array for CRC calculation
        :return: CRC-32/MPEG-2 for this bytes array
        """
        poly = 0x04C11DB7
        crc = 0xFFFFFFFF
        for byte in data:
            crc ^= (byte << 24)
            for i in range(0, 8):
                if crc & 0x80000000:
                    crc = (crc << 1) ^ poly
                else:
                    crc = (crc << 1)
            crc &= 0xFFFFFFFF
        return crc
