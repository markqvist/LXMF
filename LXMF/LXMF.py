APP_NAME = "lxmf"

# WARNING! These field specifiers are floating and not
# yet final! Consider highly experiemental, and expect
# them to change in the future! You have been warned :)

FIELD_EMBEDDED_LXMS    = 0x01
FIELD_TELEMETRY        = 0x02
FIELD_TELEMETRY_STREAM = 0x03
FIELD_ICON_APPEARANCE  = 0x04
FIELD_FILE_ATTACHMENTS = 0x05
FIELD_IMAGE            = 0x06
FIELD_AUDIO            = 0x07
FIELD_THREAD           = 0x08
FIELD_COMMANDS         = 0x09
FIELD_RESULTS          = 0x0A
FIELD_GROUP            = 0x0B
FIELD_COT              = 0x0C # Cursor on Target for TAK integration

# Audio modes for the data structure in FIELD_AUDIO

# Codec2 Audio Modes
AM_CODEC2_450PWB       = 0x01
AM_CODEC2_450          = 0x02
AM_CODEC2_700C         = 0x03
AM_CODEC2_1200         = 0x04
AM_CODEC2_1300         = 0x05
AM_CODEC2_1400         = 0x06
AM_CODEC2_1600         = 0x07
AM_CODEC2_2400         = 0x08
AM_CODEC2_3200         = 0x09

# Opus Audio Modes
AM_OPUS_OGG            = 0x10
AM_OPUS_LBW            = 0x11
AM_OPUS_MBW            = 0x12
AM_OPUS_PTT            = 0x13
AM_OPUS_RT_HDX         = 0x14
AM_OPUS_RT_FDX         = 0x15
AM_OPUS_STANDARD       = 0x16
AM_OPUS_HQ             = 0x17
AM_OPUS_BROADCAST      = 0x18
AM_OPUS_LOSSLESS       = 0x19

# Custom, unspecified audio mode, the
# client must determined it itself
AM_CUSTOM              = 0xFF
