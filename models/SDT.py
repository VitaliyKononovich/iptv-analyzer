class SDT:
    """
    Service Description Table (SDT) describes services that are contained within a particular TS.
    """
    def __init__(self):
        self.table_id = 0               # Table ID
        self.transport_stream_id = 0    # Transport Stream ID
        self.ver_num = 0                # Version number
        self.cur_next_ind = 0           # Current Next Indicator
        self.sec_num = 0                # Section Number
        self.last_sec_num = 0           # Last Section Number
        self.original_network_id = 0    # Original Network ID
        self.services = []              # Services with descriptors
        self.crc32 = 0                  # 32-bit CRC
        self.crc32_ok = True            # Status of CRC verification
