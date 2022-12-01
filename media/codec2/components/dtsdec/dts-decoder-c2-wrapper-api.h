#ifndef DTS_DECODER_C2_WRAPPER_API_H
#define DTS_DECODER_C2_WRAPPER_API_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define DTS_DEC_MAX_CHANNELS       12 /* Maximum number of output channels */

typedef void *dtsHandleType;

typedef enum
{
    DTS_DEC_ERROR_OK = 0,                /**< API completed execution without errors */
    DTS_DEC_ERROR_OUT_OF_MEMORY = -1000, /**< Decoder library has run out of memory */
    DTS_DEC_ERROR_INVALID_PARAM = -1001, /**< Invalid parameter passed as argument to the API */
    DTS_DEC_ERROR_FILE_OPEN_FAILED = -1002, /**< Failed to open the input bitstream */
    DTS_DEC_ERROR_FILE_CLOSE_FAILED = -1003, /**< Failed to close the input file */
    DTS_DEC_ERROR_FILE_SEEK_FAILED = -1004, /**< Failed to seek the input file */
    DTS_DEC_ERROR_FILE_READ_FAILED = -1005, /**< Failed to read the input bitstream */
    DTS_DEC_ERROR_SEEK_FUNCTION = -1006, /**< Failure in seeking  */
    DTS_DEC_ERROR_NOT_DTS_FILE = -1007, /**< Error in finding the DTSX file */
    DTS_DEC_ERROR_DTS_HEADER = -1008, /**< Error in the DTSX header */
    DTS_DEC_ERROR_OUTPUTFILE_OPEN_FAILED = -1009, /**< Failed to open the output file */
    DTS_DEC_ERROR_FILE_WRITER_FAILED = -1010, /**< Failed to write the output file */
    DTS_DEC_ERROR_BSINFO_UNAVAILABLE = -1011, /**< BitstreamInformation of stream
                                                   is not available */
    DTS_DEC_ERROR_TRANSCODER = -1012, /**< Failure in Transcoder */
    DTS_DEC_ERROR_AUDIOCHUNK = -1013, /**< Invalid AudioChunk */
    DTS_DEC_ERROR_OBJECT = -1014, /**< Metadata doesn't have requested Object  */
    DTS_DEC_ERROR_AUDIO_PRESENTATION = -1015, /**< Metadata doesn't have requested
                                                   AudioPresentation */
    DTS_DEC_ERROR_STREAM_NOT_SUPPORTED = -1016, /**< Stream is not supported */
    DTS_DEC_ERROR_CRC_FAILED = -1017, /**< CRC Failed */
    DTS_DEC_ERROR_STREAM_VERSION = -1018, /**< Invalid stream version */
    DTS_DEC_ERROR_INVALID_STREAM = -1019, /**< Stream is not correct */
    DTS_DEC_ERROR_DECODING = -1020, /**< Error in decoding  */
    DTS_DEC_ERROR_PROCESSING = -1021, /**< Error in postprocessing */
    DTS_DEC_ERROR_STREAM_HAS_CHANGED = -1022, /**< Bit stream channel layout has changed compared
                                                   to the previous frame. Restart the decoder  */
    DTS_DEC_ERROR_STATIC_CONFIG_PARAM = -1023, /**< Static configuration parameters are not
                                                    allowed to be updated during run-time
                                                    (unless the bus gets disabled through the
                                                    API first) */
    DTS_DEC_ERROR_NOT_WAV_FILE = -1024, /**< Error in finding the wav file */
    DTS_DEC_ERROR_NOT_SUPPORT = -1025, /**< Decoder library does not support the operation */
    DTS_DEC_ERROR_INIT_FAILED = -1200, /* Initialization failed */
    DTS_DEC_WARNING_NO_VALID_SYNCFRAME = 6000, /**< Metadata doesn't have valid Sync frame */
    DTS_DEC_WARNING_UNRECOGNIZED_PARAM = 6001, /**< Unrecognized API parameter id */
    DTS_DEC_WARNING_READ_ONLY_PARAM = 6002, /**< Parameter is read only */
    DTS_DEC_WARNING_FRAME_SKIPPED = 6003, /**< Frame was skipped due to an error */
    DTS_DEC_WARNING_MODULE_NOT_RUNNING = 10001, /**< Module was not running due to an error */
} dtsDecResult;

typedef struct
{
    uint32_t nSpkrOut;                     /**< Desired output speaker layout mask.
                                                Range : 0x00000000 = Bypass down-mixing. \n
                                                        0x00000002 = 2.0 \n
                                                        0x0000000F = 5.1 \n
                                                        0x0000002F = 5.1.2 \n
                                                        0x0000802F = 5.1.4 \n
                                                        0x0000000A = 2.1 \n
                                                        0x00000022 = 2.0.2 \n
                                                        0x0000002A = 2.1.2 \n
                                                        0x00000003 = 3.0 \n
                                                        0x0000000B = 3.1 \n
                                                        0x00000023 = 3.0.2 \n
                                                        0x0000002B = 3.1.2 \n
                                                        0x00000007 = 5.0 \n
                                                        0x00000027 = 5.0.2 \n
                                                        0x00008027 = 5.0.4 \n
                                                        0x00000843 = 7.0 \n
                                                        0x0000084B = 7.1 \n
                                                        0x00000863 = 7.0.2 \n
                                                        0x0000086B = 7.1.2 \n
                                                        0x00008863 = 7.0.4 \n
                                                        0x0000886B = 7.1.4 \n
                                                        Default : 0x0000802F */
    int32_t bLoudnessNormEnable;           /**< Enable/disable the loudness normalization.\n
                                                        Range   : 0 = Disable \n
                                                                  1 = Enable \n
                                                        Default : 1 */
    int32_t nLoundnessNormTarget;          /**< Output target value for the Loudness Normalization
                                                (also referred to as the target loudness).
                                                Range   :
                                                        If the limiter type has been set to 0
                                                        (Hybrid unlinked):\n
                                                            -60 to -10 (in dB in steps of 1) \n
                                                        If the limiter type has been set to 1
                                                        (Hybrid linked):\n
                                                            -60 to -27 (in dB in steps of 1) \n
                                                        If the limiter type has been set to 2
                                                        (Hard-clipper) or 3 (Hard-clipper all):\n
                                                            -60 to -31 (in dB in steps of 1) \n
                                                Default : -24 */
    int32_t bDRCEnable;                    /**< To enable/disable the DRC (Dynamic Range
                                                Compression) processing. \n
                                                Range   : 0 = Disable \n
                                                          1 = Enable \n
                                                Default : 0*/
    int32_t nDRCMode;                      /**< Select one of the three DRC types/profiles
                                                (Low, Medium, or High).\n
                                                Range   : 0 = Low \n
                                                          1 = Medium \n
                                                          2 = High \n
                                                Default : 1 */
    int32_t nLowDRCTypeCurveSelect;
    int32_t nMediumDRCTypeCurveSelect;
    int32_t nHighDRCTypeCurveSelect;        /**< To select one of the fifteen DRC pre-defined
                                                 compression curves for a selected DRC
                                                 type/profile.\n
                                                 (NOTE: Each DRC pre-defined compression curve
                                                 selection is associated with a specific DRC
                                                 type/profile.
                                                 Hence, it's necessary to select the DRC
                                                 type/profile first before a DRC pre-defined
                                                 compression curve is selected)\n
                                                 Range: 0 = No Compression (Disables DRC)\n
                                                        1 = Legacy Film Standard (Limits the
                                                            loudest scenes, whilst boosting the
                                                            quiet passages.
                                                            Late night movie watching whilst others
                                                            are sleeping) \n
                                                        2 = Legacy Film light (Limits the loudest
                                                            scenes a little, whilst only boosting
                                                            the very quiet passages.
                                                            Avoids disturbing the neighbors and
                                                            preserves some of the dynamics)
                                                        3 = Legacy Music Standard (Limits the
                                                            loudest scenes, whilst boosting the
                                                            quiet passages, with more boost than
                                                            film mode, as background noise is not
                                                            as common for music – listening to
                                                            classical music with long quiet
                                                            passages late at night without
                                                            disturbing other people in the house.
                                                        4 = Legacy Music light (Very light
                                                            compression boosting only the quietest
                                                            sections and reducing the loudest peaks
                                                            a little.
                                                            Daytime listening to avoid disturbing
                                                            the neighbors)
                                                        5 = Legacy speech (Very high compression.
                                                            Very aggressive boost, making all
                                                            quieter sections significantly louder)
                                                        6 = Low DRC – Less Attenuation
                                                            (Light compression for an environment
                                                            with background noise
                                                            (e.g., A/C or refrigerator).
                                                            It will boost the quiet passages to
                                                            make them au-dible over the background
                                                            noise,
                                                            but not attenuate the loud scenes so
                                                            much.)  \n
                                                        7 = Low DRC – Less Boost (Light compression
                                                            for a quiet environment, but with loud
                                                            content con-trolled more.
                                                            Ideal to minimize disturbing others in
                                                            the house, or if your speaker system is
                                                            limited and cannot produce
                                                            high levels for the loud scenes.)  \n
                                                        8 = Low DRC – Symmetrical (Light full
                                                            compression of loud and quiet content
                                                            toward the target.
                                                            The user wants to watch a movie without
                                                            disturbing the neighbors, but still
                                                            would like to
                                                            preserve a fair bit of Dynamic
                                                            range.)  \n
                                                        9 = Medium DRC – Less Attenuation
                                                            (Medium compression for an environment
                                                            with background noise
                                                            (e.g., A/C or refrigerator). It will
                                                            boost the quiet passages to make them
                                                            audible over the
                                                            background noise, but not attenuate the
                                                            loud scenes so much.) \n
                                                        10 = Medium DRC – Less Boost(Medium
                                                             compression for a quiet environment,
                                                             but with loud content
                                                             controlled more. Ideal to minimize
                                                             disturbing others in the house, or if
                                                             your speaker system
                                                             is limited and cannot produce high
                                                             levels for the loud scenes.) \n
                                                        11 = Medium DRC – Symmetrical (Medium full
                                                             compression of loud and quiet content
                                                             toward the target.
                                                             The user wants to watch a movie
                                                             without disturbing the neighbors.) \n
                                                        12 = High DRC – Less Attenuation (High
                                                             compression for an environment with
                                                             loud background noise
                                                             (e.g., machinery, loud engine noise).
                                                             It will boost the quiet passages to
                                                             make them audible
                                                             over the background noise, but not
                                                             attenuate the loud scenes so much.) \n
                                                        13 = High DRC – Less Boost (High
                                                             compression for a quiet environment,]
                                                             but with loud content
                                                             controlled more. Ideal to minimize
                                                             disturbing people sleeping in
                                                             another room.) \n
                                                        14 = High DRC – Symmetrical (High full
                                                             compression of loud and quiet content
                                                             toward the target.
                                                             The user wants to watch a movie
                                                             without disturbing the neighbors.
                                                             The dynamic range of the output
                                                             is very low.) \n
                                                Default: DRC Low type/profile    - 8 \n
                                                         DRC Medium type/profile - 11 \n
                                                         DRC High type/profile   - 14 \n */
    int32_t nDRCBoostPercent;              /**< Specify how much (in percentage) of the DRC gain
                                                factor to apply to the PCM samples during
                                                the DRC processing.\n
                                                Range   : 0 - 100 \n
                                                Default : 100 */
    int32_t nDRCAttenPercent;              /**< Specify how much (in percentage) of the DRC
                                                attenuation factor to apply to the PCM samples
                                                during the DRC processing. \n
                                                Range   : 0 - 100 \n
                                                Default : 100 */
    int32_t nLimiterType;                  /**< Select the limiter type.\n
                                                Range   :
                                                If target loudness has been set less than or equal
                                                to -10 dB: \n
                                                    0 = Hybrid limiting in un-linked mode (Highest
                                                    MIPS) \n
                                                If target loudness has been set less than or equal
                                                to -27 dB: \n
                                                    0 = Hybrid limiting in un-linked mode (Highest
                                                    MIPS) \n
                                                    1 = Hybrid limiting in linked mode
                                                    (Medium MIPS) \n
                                                If target loudness has been set less than or equal
                                                to -31 dB: \n
                                                    0 = Hybrid limiting in un-linked mode
                                                    (Highest MIPS) \n
                                                    1 = Hybrid limiting in linked mode
                                                    (Medium MIPS) \n
                                                    2 = Hard-clipper limiting on all channels
                                                    except LFE (Slightly higher than lowest
                                                    MIPS) \n
                                                    3 = Hard-clipper limiting on all channels
                                                    including LFE (Lowest MIPS) \n
                                                Default : 0*/
} dtsC2ConfigParam;

typedef struct
{
    uint8_t *pBuffer;
    uint32_t nAllocSize;
    uint32_t nFrameSize;
    uint32_t nOffset;
    uint32_t nFlags;
    uint32_t nFilledLen;
} dtsC2InputBufferConfig;

typedef struct
{
    uint8_t *pBuffer;
    uint32_t nAllocSize;
    uint32_t nFrameSize;
    uint32_t nOffset;
} dtsC2OutputBufferConfig;

/** Output format description */
typedef struct {
    uint32_t nChannels;       /* Number of output channels (e.g. 2 for stereo) */
    uint32_t nSamplingRate;   /* Output sampling rate */
    uint32_t nBitPerSample;   /* Bits per sample */

    /* Below params are for testing purpose only */
    uint32_t nRepTypes;       /* Indicates the representation type of encoded audio, if it requires
                                 any downstream post-processing.
                                 Common values are, 1: Ambisonic/Unmapped, 2:Lt/Rt, 3:Lh/Rh */
    int32_t eChannelMapping[DTS_DEC_MAX_CHANNELS]; /* Mapping of output channels in DTS Channel
                                                      order */
} dtsC2OutputDescriptor;

typedef struct
{
    void *pComponentPrivate;
    dtsC2OutputDescriptor *pOutputInfo;
}dtsC2WrapperInstance;

typedef struct
{
    /* API returns the size(in bytes) of instance memory needed by the DTS decoder component */
    int32_t( *DTS_Dec_GetSizeOf )( );
    /* API for initializing the allocated instance memory */
    dtsDecResult( *DTS_Dec_Initialize )( dtsHandleType );
    /* API for de-initializing the decoder instance */
    dtsDecResult( *DTS_Dec_DeInitialize )( dtsHandleType );
    /* API which decodes one frame of DTS audio */
    dtsDecResult( *DTS_Dec_DecodeFrame )( dtsHandleType,
        dtsC2InputBufferConfig *pBuffer_in,
        dtsC2OutputBufferConfig *pBuffer_out );
    /* API which gets the current value of configuration prameters from decoder */
    dtsDecResult ( *DTS_Dec_GetParam )( dtsHandleType, dtsC2ConfigParam * );
    /* API which apply any configuration prameter updates to decoder */
    dtsDecResult ( *DTS_Dec_SetParam )( dtsHandleType, dtsC2ConfigParam * );
}dtsC2WrapperAPIs;

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* #ifndef DTS_DECODER_C2_WRAPPER_API_H */
