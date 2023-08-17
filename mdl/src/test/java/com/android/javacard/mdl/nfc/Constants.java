package com.android.javacard.mdl.nfc;

import static java.lang.annotation.RetentionPolicy.SOURCE;

import java.lang.annotation.Retention;

/**
 * Various constants used by other classes.
 */
public class Constants {

  /**
   * Normal processing. This status message shall be
   * returned if no other status is returned.
   *
   * <p>This value is defined in ISO/IEC 18013-5 Table 8.
   */
  public static final long DEVICE_RESPONSE_STATUS_OK = 0;
  /**
   * The mdoc returns an error without any given
   * reason. No data is returned.
   *
   * <p>This value is defined in ISO/IEC 18013-5 Table 8.
   */
  public static final long DEVICE_RESPONSE_STATUS_GENERAL_ERROR = 10;
  /**
   * The mdoc indicates an error during CBOR decoding
   * that the data received is not valid CBOR. Returning
   * this status code is optional.
   *
   * <p>This value is defined in ISO/IEC 18013-5 Table 8.
   */
  public static final long DEVICE_RESPONSE_STATUS_CBOR_DECODING_ERROR = 11;
  /**
   * The mdoc indicates an error during CBOR
   * validation, e.g. wrong CBOR structures. Returning
   * this status code is optional.
   *
   * <p>This value is defined in ISO/IEC 18013-5 Table 8.
   */
  public static final long DEVICE_RESPONSE_STATUS_CBOR_VALIDATION_ERROR = 12;
  /**
   * If this flag is set, {PresentationHelper} and {@link VerificationHelper}
   * will log informational messages.
   */
  public static final int LOGGING_FLAG_INFO = (1 << 0);
  /**
   * If this flag is set, { PresentationHelper} and {@link VerificationHelper}
   * will log messages related to Device Engagement.
   */
  public static final int LOGGING_FLAG_ENGAGEMENT = (1 << 1);
  /**
   * If this flag is set, { PresentationHelper} and {@link VerificationHelper}
   * will log messages related to session layer encryption including the
   * the hexadecimal representation of the cleartext messages in {@code SessionData}
   * and {@code SessionEstablishment} CBOR messages that are sent and received.
   *
   * <p>This might generate a lot of data.
   */
  public static final int LOGGING_FLAG_SESSION = (1 << 2);
  /**
   * If this flag is set, {PresentationHelper} and {@link VerificationHelper}
   * will log transport specific high-level messages. For the actual content of
   * each packet, use {@link #LOGGING_FLAG_TRANSPORT_VERBOSE}.
   */
  public static final int LOGGING_FLAG_TRANSPORT = (1 << 3);
  /**
   * If this flag is set, { PresentationHelper} and {@link VerificationHelper}
   * will log transport-specific data packets, for example APDUs for NFC transport.
   *
   * <p>This might generate a lot of data.
   */
  public static final int LOGGING_FLAG_TRANSPORT_VERBOSE = (1 << 4);

  /**
   * Constant to request maximum amount of logging when using { PresentationHelper} and
   * {@link VerificationHelper}.
   *
   * <p>This is useful for e.g. tests using these primitives.
   */
  public static final int LOGGING_FLAG_MAXIMUM = Integer.MAX_VALUE;

  /**
   * Flag indicating that the <em>mdoc central client mode</em> should be supported
   * for BLE data retrieval.
   */
  public static final int BLE_DATA_RETRIEVAL_OPTION_MDOC_CENTRAL_CLIENT_MODE = (1 << 0);
  /**
   * Flag indicating that the <em>mdoc peripheral server mode</em> should be supported
   * for BLE data retrieval.
   */
  public static final int BLE_DATA_RETRIEVAL_OPTION_MDOC_PERIPHERAL_SERVER_MODE = (1 << 1);
  /**
   * Flag indicating that L2CAP should be used for data retrieval if available and supported.
   */
  public static final int BLE_DATA_RETRIEVAL_OPTION_L2CAP = (1 << 2);
  /**
   * Flag indicating that BLE Services Cache should be cleared before service discovery
   * when acting as a GATT Client.
   */
  public static final int BLE_DATA_RETRIEVAL_CLEAR_CACHE = (1 << 3);

  /**
   * The status code of the document response.
   *
   * These values are defined in ISO/IEC 18013-5 Table 8.
   *
   * @hidden
   */
  @Retention(SOURCE)
  @LongDef({DEVICE_RESPONSE_STATUS_OK,
      DEVICE_RESPONSE_STATUS_GENERAL_ERROR,
      DEVICE_RESPONSE_STATUS_CBOR_DECODING_ERROR,
      DEVICE_RESPONSE_STATUS_CBOR_VALIDATION_ERROR})
  public @interface DeviceResponseStatus {
  }

  /**
   * Logging flags.
   *
   * @hidden
   */
  @Retention(SOURCE)
  @IntDef(
      flag = true,
      value = {
          LOGGING_FLAG_INFO,
          LOGGING_FLAG_ENGAGEMENT,
          LOGGING_FLAG_SESSION,
          LOGGING_FLAG_TRANSPORT,
          LOGGING_FLAG_TRANSPORT_VERBOSE
      })
  public @interface LoggingFlag {
  }

  /**
   * BLE data retrieval flags.
   *
   * @hidden
   */
  @Retention(SOURCE)
  @IntDef(
      flag = true,
      value = {
          BLE_DATA_RETRIEVAL_OPTION_MDOC_CENTRAL_CLIENT_MODE,
          BLE_DATA_RETRIEVAL_OPTION_MDOC_PERIPHERAL_SERVER_MODE,
          BLE_DATA_RETRIEVAL_OPTION_L2CAP,
          BLE_DATA_RETRIEVAL_CLEAR_CACHE
      })
  public @interface BleDataRetrievalOption {
  }

}