class PES:
    """
    Packetized Elementary Stream (PES) transmitting elementary stream data from a video or audio encoder
    Is a specification in the MPEG-2 Part 1 (Systems) (ISO/IEC 13818-1) and ITU-T H.222.0
    """
    def __init__(self):
        self.stream_id = 0                      # Stream ID
        self.stream_type = None                 # Stream type: audio or video
        self.stream_number = 0                  # Version number
        self.PES_scrambling_control = False     # PES scrambling control
        self.copyright = False                  # Copyright
        self.original_or_copy = False           # Content is Original or copy
        self.PTS_DTS_flags = 0                  # PTS DTS flags
        self.ESCR_flag = False                  # ESCR flag
        self.ES_rate_flag = False               # ES rate flag
        self.DSM_trick_mode_flag = False        # DSM trick mode flag
        self.additional_copy_info_flag = False  # Additional copy info flag
        self.PES_CRC_flag = False               # PES CRC flag
        self.PES_extension_flag = False         # PES extension flag
        self.PTS = None                         # PTS (presentation time stamp)
        self.DTS = None                         # DTS (decoding time stamp)
