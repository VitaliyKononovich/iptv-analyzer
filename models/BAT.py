class BAT:
    """
    Bouquet Association Table (BAT) provides information regarding bouquets. A bouquet is a collection of services,
    which may traverse the boundary of a network.
    """
    def __init__(self):
        self.table_id = 0               # Table ID
        self.bouquet_id = 0             # Bouquet ID
        self.ver_num = 0                # Version number
        self.cur_next_ind = 0           # Current Next Indicator
        self.sec_num = 0                # Section Number
        self.last_sec_num = 0           # Last Section Number
        self.descriptors = []           # Bouquet descriptors
        self.transport_streams = []     # Transport streams
        self.crc32 = 0                  # 32-bit CRC
        self.crc32_ok = True            # Status of CRC verification