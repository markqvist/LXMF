APP_NAME = "lxmf"

##########################################################
# The following core fields are provided to facilitate   #
# interoperability in data exchange between various LXMF #
# clients and systems.                                   #
##########################################################
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
FIELD_TICKET           = 0x0C
FIELD_EVENT            = 0x0D

# For usecases such as including custom data structures,
# embedding or encapsulating other data types or protocols
# that are not native to LXMF, or bridging/tunneling
# external protocols or services over LXMF, the following
# fields are available. A format/type/protocol (or other)
# identifier can be included in the CUSTOM_TYPE field, and
# the embedded payload can be included in the CUSTOM_DATA
# field. It is up to the client application to correctly
# discern and potentially utilise any data embedded using
# this mechanism.
FIELD_CUSTOM_TYPE      = 0xFB
FIELD_CUSTOM_DATA      = 0xFC
FIELD_CUSTOM_META      = 0xFD

# The non-specific and debug fields are intended for
# development, testing and debugging use.
FIELD_NON_SPECIFIC     = 0xFE
FIELD_DEBUG            = 0xFF

##########################################################
# The following section lists field-specific specifiers, #
# modes and identifiers that are native to LXMF. It is   #
# optional for any client or system to support any of    #
# these, and they are provided as template for easing    #
# interoperability without sacrificing expandability     #
# and flexibility of the format.                         #
##########################################################

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

# Custom, unspecified audio mode, the client must
# determine it itself based on the included data.
AM_CUSTOM              = 0xFF


##########################################################
# The following helper functions makes it easier to      #
# handle and operate on LXMF data in client programs     #
##########################################################

import RNS.vendor.umsgpack as msgpack
def display_name_from_app_data(app_data=None):
    if app_data == None:
        return None
    elif len(app_data) == 0:
        return None
    else:
        # Version 0.5.0+ announce format
        if (app_data[0] >= 0x90 and app_data[0] <= 0x9f) or app_data[0] == 0xdc:
            peer_data = msgpack.unpackb(app_data)
            if type(peer_data) == list:
                if len(peer_data) < 1:
                    return None
                else:
                    dn = peer_data[0]
                    if dn == None:
                        return None
                    else:
                        try:
                            decoded = dn.decode("utf-8")
                            return decoded
                        except:
                            RNS.log("Could not decode display name in included announce data. The contained exception was: {e}", RNS.LOG_ERROR)
                            return None

        # Original announce format
        else:
            return app_data.decode("utf-8")

def stamp_cost_from_app_data(app_data=None):
    if app_data == None or app_data == b"":
        return None
    else:
        # Version 0.5.0+ announce format
        if (app_data[0] >= 0x90 and app_data[0] <= 0x9f) or app_data[0] == 0xdc:
            peer_data = msgpack.unpackb(app_data)
            if type(peer_data) == list:
                if len(peer_data) < 2:
                    return None
                else:
                    return peer_data[1]

        # Original announce format
        else:
            return None