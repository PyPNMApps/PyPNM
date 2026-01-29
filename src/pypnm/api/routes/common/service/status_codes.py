# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

from enum import IntEnum


class ServiceStatusCode(IntEnum):
    '''
    SKIP_MESSAGE is to indicat not process the MessageResponse
    '''
    SKIP_MESSAGE_RESPONSE                   = -2
    UNKNOWN                                 = -1
    SUCCESS                                 =  0
    UNREACHABLE_PING                        =  1
    UNREACHABLE_SNMP                        =  2
    NO_PLC_FOUND                            =  3
    INVALID_PLC                             =  4
    TFTP_INET_MISMATCH                      =  5
    FILE_SET_FAIL                           =  6
    TEST_ERROR                              =  7
    MEASUREMENT_TIMEOUT                     =  8
    TFTP_SERVER_PATH_SET_FAIL               =  9
    NOT_READY_AFTER_FILE_CAPTURE            = 10
    COPY_PNM_FILE_TO_LOCAL_SAVE_DIR_FAILED  = 11
    TRANSACTION_RECORD_SET_FAILED           = 12
    UNSUPPORTED_IF_TYPE                     = 13
    NO_OFDM_CHAN_ID_INDEX_FOUND             = 14
    NO_OFDMA_CHAN_ID_INDEX_FOUND            = 15
    INVALID_INTERFACE_PARAMETERS            = 16
    FAILURE                                 = 17
    RESET_NOW_FAILED                        = 18
    PING_FAILED                             = 19
    MISSING_PNM_FILENAME                    = 20
    TFTP_PNM_FILE_UPLOAD_FAILURE            = 21
    NO_SCQAM_CHAN_ID_INDEX_FOUND            = 22
    NO_ATDMA_CHAN_ID_INDEX_FOUND            = 23
    MISSING_PNM_TEST_TYPE                   = 24
    CM_MAC_DOES_MATCH_MATCH                 = 25
    INVALID_MAC_ADDRESS_FORMAT              = 26
    INVALID_INET_ADDRESS_FORMAT             = 27

    INVALID_CAPTURE_PARAMETERS              = 90

    PNM_FILE_RETRIEVAL_ERROR                = 98
    FILE_RETRIEVAL_TYPE_INVALID             = 99

    SCP_PNM_FILE_FETCH_ERROR                = 100
    SFTP_PNM_FILE_FETCH_ERROR               = 101
    TFTP_PNM_FILE_FETCH_ERROR               = 102
    FTP_PNM_FILE_FETCH_ERROR                = 103
    HTTP_PNM_FILE_FETCH_ERROR               = 104
    SHTTP_PNM_FILE_FETCH_ERROR              = 105
    LOCAL_FETCH_FAILURE                     = 106

    SCP_HOST_UNREACHABLE                    = 110
    SFTP_HOST_UNREACHABLE                   = 111
    TFTP_HOST_UNREACHABLE                   = 112
    FTP_HOST_UNREACHABLE                    = 113
    HTTP_HOST_UNREACHABLE                   = 114
    SHTTP_HOST_UNREACHABLE                  = 115
    LOCAL_HOST_UNREACHABLE                  = 116

    INVALID_DOCSIS_VERSION                  = 120
    NO_OFDMA_CHANNELS_EXIST                 = 121
    NO_OFDM_CHANNELS_EXIST                  = 122
    INVALID_CHANNEL_ID                      = 123

    TRANSACTION_RECORD_GET_FAILED           = 200
    UNSUPPORTED_TEST_TYPE                   = 201
    CAPTURE_GROUP_NOT_FOUND                 = 202
    PNM_FILE_TRANSACTION_ID_NOT_FOUND       = 203

    INVALID_OUTPUT_TYPE                     = 220

    DS_OFDM_RXMER_NOT_AVAILABLE             = 300

    SPEC_ANALYZER_NOT_AVAILABLE             = 400
    SPEC_ANALYZER_AMPLITUDE_DATA_TIMEOUT    = 401
    SPEC_ANALYZER_AMPLITUDE_DATA_NOT_FOUND  = 402
    SPEC_ANALYZER_DATA_RETRIVAL_ERROR       = 403
    SPEC_ANALYZER_SET_CONFIG_ERROR          = 404

    DS_OFDM_MULIT_RXMER_FAILED              = 500
    MEASURE_MODE_INVALID                    = 501
    DS_OFDM_MULIT_RXMER_ANALYSIS_TYPE       = 502

    DS_OFDM_CHAN_EST_NOT_AVAILABLE          = 550
    DS_OFDM_CHAN_EST_INVALID_ANALYSIS_TYPE  = 551

    US_OFDMA_PRE_EQ_NOT_AVAILABLE           = 600
    US_OFDMA_PRE_EQ_INVALID_ANALYSIS_TYPE   = 601

    DS_OFDM_FEC_SUMMARY_NOT_AVALIABLE       = 700

    DS_OFDM_MOD_PROFILE_NOT_AVALAIBLE       = 800

    NO_SPECTRUM_CAPTURE_PARAMETERS          = 1000
