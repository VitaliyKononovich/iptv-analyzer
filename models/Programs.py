from models.PAT import PAT
from models.PMT import PMT
from models.CAT import CAT
from models.SDT import SDT


class Programs:
    """
    Class contains information about transmitted programs in TS stream/ This information based on PAT, PTM, CAT, SDT
    and other control packets in TS stream
    """
    def __init__(self):
        self.__pat = None
        self.__pmt = dict()
        self.__pmt_pids = set()
        self.__net_pids = set()
        self.__pcr_pids = set()
        self.__stream_pids = set()
        self.__other_pids = set()
        self.__cat = None
        self.__sdt = None

    @property
    def pat(self) -> PAT:
        return self.__pat

    @pat.setter
    def pat(self, pat: PAT):
        self.__pat = pat
        for prog in pat.prog_nums:
            if prog['program_number'] == 0:
                self.__net_pids.add(prog['network_PID'])
            else:
                self.__pmt_pids.add(prog['program_map_PID'])

    def update_pat(self, pat: PAT):
        for prog in self.__pat.prog_nums:
            if prog['program_number'] == 0:
                self.__net_pids.remove(prog['network_PID'])
            else:
                self.__pmt_pids.remove(prog['program_map_PID'])
        self.pat = pat

    def get_pmt_pids(self) -> set:
        return self.__pmt_pids

    def get_net_pids(self) -> set:
        return self.__net_pids

    def get_stream_pids(self) -> set:
        return self.__stream_pids

    def get_other_pids(self) -> set:
        return self.__other_pids

    def get_prog_pmt(self, pid: int) -> PMT:
        if pid in self.__pmt_pids:
            return self.__pmt.get(str(pid), None)
        else:
            return None

    def set_prog_pmt(self, pid: int, pmt: PMT):
        if pid in self.__pmt_pids:
            self.__pmt[str(pid)] = pmt
            self.__stream_pids |= set([stream['elementary_pid'] for stream in pmt.streams])
            self.__other_pids |= set([desc['descriptor_data']['ca_pid'] for desc in pmt.descriptors if desc['descriptor_tag'] == 9])
            self.__pcr_pids.add(pmt.pcr_pid)

    def update_prog_pmt(self, pid: int, pmt: PMT):
        if pid in self.__pmt_pids:
            self.__stream_pids -= set([stream['elementary_pid'] for stream in self.__pmt[str(pid)].streams])
            self.__other_pids -= set([desc['descriptor_data']['ca_pid'] for desc in self.__pmt[str(pid)].descriptors if desc['descriptor_tag'] == 9])
            self.__pcr_pids.remove(self.__pmt[str(pid)].pcr_pid)
            self.set_prog_pmt(pid, pmt)

    def get_pcr_pids(self) -> set:
        return self.__pcr_pids

    @property
    def cat(self) -> CAT:
        return self.__cat

    @cat.setter
    def cat(self, cat: CAT):
        self.__cat = cat
        self.__other_pids |= set([desc['descriptor_data']['ca_pid'] for desc in cat.descriptors if desc['descriptor_tag'] == 9])

    @property
    def sdt(self) -> SDT:
        return self.__sdt

    @sdt.setter
    def sdt(self, sdt: SDT):
        self.__sdt = sdt

