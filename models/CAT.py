class CAT:
    """
    Conditional Access Table (CAT) provides the association between one or more CA systems
    """
    def __init__(self):
        self.table_id = 0       # Table ID
        self.ver_num = 0        # Version number
        self.cur_next_ind = 0   # Current Next Indicator
        self.sec_num = 0        # Section Number
        self.last_sec_num = 0   # Last Section Number
        self.descriptors = []   # Descriptor
        self.crc32 = 0          # 32-bit CRC
        self.crc32_ok = True    # Status of CRC verification
