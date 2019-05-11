class TSPacket:
    """
    Transport Stream Packet is the basic unit of data in a transport stream
    https://en.wikipedia.org/wiki/MPEG_transport_stream#Packet
    """
    def __init__(self):
        # 4-byte Transport Stream Header
        self.tsh_sync = 0       # Sync byte (Bit pattern of 0x47 (ASCII char 'G'))
        self.tsh_tei = 0        # Transport Error Indicator (TEI)
        self.tsh_pusi = 0       # Payload Unit Start Indicator (PUSI)
        self.tsh_tp = 0         # Transport Priority
        self.tsh_pid = 0        # PID
        self.tsh_tsc = None       # Transport Scrambling Control (TSC)
        self.tsh_afc = None       # Adaptation field control
        self.tsh_cc = None        # Continuity counter

        # Adaptation Field
        self.af_length = 0          # Adaptation Field Length
        self.af_disc = False        # Discontinuity indicator
        self.af_random = False      # Random Access indicator
        self.af_espi = False        # Elementary stream priority indicator
        self.af_pcrf = False        # PCR flag
        self.af_opcrf = False       # OPCR flag
        self.af_spf = False         # Splicing point flag
        self.af_tpdf = False        # Transport private data flag
        self.af_afef = False        # Adaptation field extension flag

        self.af_pcr = None          # Program clock reference (PCR)
        self.af_opcr = None         # Original Program clock reference (OPCR)
        self.af_sc = None           # Splice countdown
        self.af_tpd = None          # Transport private data
        self.af_ae = None           # Adaptation extension

        self.payload = 0            # Payload byte number
        self.error = None           # Set error text if error occurred during TS parsing

        self.dt = None              # datetime timestamp

    def __str__(self):
        return '\tPID=0x{:04X}\tCC={}'.format(self.tsh_pid, self.tsh_cc)
