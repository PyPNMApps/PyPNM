
from __future__ import annotations

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia
from enum import IntEnum


class DocsPnmBulkUploadControl(IntEnum):
    """
    Enum for DocsPnmBulkUploadControl SNMP object.

    Values:
        OTHER (1): Undefined or unspecified behavior.
        NO_AUTO_UPLOAD (2): Bulk data files are not automatically uploaded.
        AUTO_UPLOAD (3): Bulk data files are automatically uploaded when available.
    """
    OTHER = 1
    NO_AUTO_UPLOAD = 2
    AUTO_UPLOAD = 3

class InetAddressType(IntEnum):
    """
    Enum representing the InetAddressType textual convention from SNMP MIBs.

    It defines types of Internet addresses used in network management.

    Module INET-ADDRESS-MIB (RFC 3291:05/2002)

    Values:
        UNKNOWN (0): An unknown address type.
        IPV4 (1): An IPv4 address.
        IPV6 (2): A global IPv6 address.
        IPV4Z (3): A non-global IPv4 address with a zone index.
        IPV6Z (4): A non-global IPv6 address with a zone index.
        DNS (16): A DNS domain name.

    Notes:
        - The value 0 (UNKNOWN) should be used for zero-length addresses or addresses of undefined type.
        - Address type and corresponding InetAddress values must be consistent according to SNMP standards.
    """

    UNKNOWN = 0
    IPV4 = 1
    IPV6 = 2
    IPV4Z = 3
    IPV6Z = 4
    DNS = 16

class DocsisIfType(IntEnum):
    ethernetCsmacd           = 6     # Ethernet-like interface
    voiceEM                  = 100   # Voice recEive and transMit
    voiceFXO                 = 101   # Voice Foreign Exchange Office
    voiceFXS                 = 102   # Voice Foreign Exchange Station
    voiceEncap               = 103   # Voice encapsulation
    voiceOverIp              = 104   # Voice over IP encapsulation
    docsCableMaclayer           = 127   # CATV MAC Layer
    docsCableDownstream         = 128   # CATV Downstream Interface
    docsCableUpstream           = 129   # CATV Upstream Interface
    voiceOverAtm                = 152   # Voice Over ATM
    voiceOverFrameRelay         = 153   # Voice Over Frame Relay
    voiceOverCable              = 198   # Voice Over Cable Interface
    docsCableUpstreamChannel    = 205   # CATV Upstream Channel
    voiceEMFGD                  = 211   # voice E&M Feature Group D
    voiceFGDEANA                = 212   # voice FGD Exchange Access North American
    voiceDID                    = 213   # voice Direct Inward Dialing
    voiceFGDOS                  = 235   # voice FGD Operator Services
    voiceEBS                    = 245   # voice P-phone EBS physical interface
    docsCableUpstreamRfPort     = 256   # DOCSIS Upstream RF Port
    cableDownstreamRfPort       = 257   # CATV downstream RF port
    docsOfdmDownstream          = 277   # DOCSIS Downstream OFDM Interface
    docsOfdmaUpstream           = 278   # DOCSIS Upstream OFDMA Interface
    docsCableScte55d1FwdOob     = 283   # Cable SCTE 55-1 OOB Forward Channel
    docsCableScte55d1RetOob     = 284   # Cable SCTE 55-1 OOB Return Channel
    docsCableScte55d2DsOob      = 285   # Cable SCTE 55-2 OOB Downstream Channel
    docsCableScte55d2UsOob      = 286   # Cable SCTE 55-2 OOB Upstream Channel
    docsCableNdf                = 287   # Cable Narrowband Digital Forward
    docsCableNdr                = 288   # Cable Narrowband Digital Return
