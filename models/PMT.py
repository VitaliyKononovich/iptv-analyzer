class PMT:
    """
    Program Map Table (PMT) specifies PID values for components of one or more programs
    """
    def __init__(self):
        self.table_id = 0       # Table ID
        self.prog_num = 0       # Program number
        self.ver_num = 0        # Version number
        self.cur_next_ind = 0   # Current Next Indicator
        self.sec_num = 0        # Section Number
        self.last_sec_num = 0   # Last Section Number
        self.pcr_pid = 0        # PID of the TS packets which shall contain the PCR fields
        self.descriptors = []   # Program descriptors
        self.streams = []       # Program TSs
        self.crc32 = 0          # 32-bit CRC
        self.crc32_ok = True    # Status of CRC verification
