package com.android.javacard.mdl.nfc;

import java.net.URISyntaxException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.net.URI;
import androidx.annotation.Nullable;

// This is copied from AOSP and refactored to depend only on Java platform
public class NdefRecord {
  /**
   * Indicates the record is empty.<p>
   * Type, id and payload fields are empty in a {@literal TNF_EMPTY} record.
   */
  public static final short TNF_EMPTY = 0x00;

  /**
   * Indicates the type field contains a well-known RTD type name.<p>
   * Use this tnf with RTD types such as {@link #RTD_TEXT}, {@link #RTD_URI}.
   * <p>
   * The RTD type name format is specified in NFCForum-TS-RTD_1.0.
   *
   * @see #RTD_URI
   * @see #RTD_TEXT
   * @see #RTD_SMART_POSTER
   * @see #createUri
   */
  public static final short TNF_WELL_KNOWN = 0x01;

  /**
   * Indicates the type field contains a media-type BNF
   * construct, defined by RFC 2046.<p>
   * Use this with MIME type names such as {@literal "image/jpeg"}, or
   * using the helper {@link #createMime}.
   *
   * @see #createMime
   */
  public static final short TNF_MIME_MEDIA = 0x02;

  /**
   * Indicates the type field contains an absolute-URI
   * BNF construct defined by RFC 3986.<p>
   * When creating new records prefer {@link #createUri},
   * since it offers more compact URI encoding
   * ({@literal #RTD_URI} allows compression of common URI prefixes).
   *
   * @see #createUri
   */
  public static final short TNF_ABSOLUTE_URI = 0x03;

  /**
   * Indicates the type field contains an external type name.<p>
   * Used to encode custom payloads. When creating new records
   * use the helper {@link #createExternal}.<p>
   * The external-type RTD format is specified in NFCForum-TS-RTD_1.0.<p>
   * <p>
   * Note this TNF should not be used with RTD_TEXT or RTD_URI constants.
   * Those are well known RTD constants, not external RTD constants.
   *
   * @see #createExternal
   */
  public static final short TNF_EXTERNAL_TYPE = 0x04;

  /**
   * Indicates the payload type is unknown.<p>
   * NFC Forum explains this should be treated similarly to the
   * "application/octet-stream" MIME type. The payload
   * type is not explicitly encoded within the record.
   * <p>
   * The type field is empty in an {@literal TNF_UNKNOWN} record.
   */
  public static final short TNF_UNKNOWN = 0x05;

  /**
   * Indicates the payload is an intermediate or final chunk of a chunked
   * NDEF Record.<p>
   * {@literal TNF_UNCHANGED} can not be used with this class
   * since all {@link NdefRecord}s are already unchunked, however they
   * may appear in the binary format.
   */
  public static final short TNF_UNCHANGED = 0x06;

  /**
   * Reserved TNF type.
   * <p>
   * The NFC Forum NDEF Specification v1.0 suggests for NDEF parsers to treat this
   * value like TNF_UNKNOWN.
   * @hide
   */
  public static final short TNF_RESERVED = 0x07;

  /**
   * RTD Text type. For use with {@literal TNF_WELL_KNOWN}.
   * @see #TNF_WELL_KNOWN
   */
  public static final byte[] RTD_TEXT = {0x54};  // "T"

  /**
   * RTD URI type. For use with {@literal TNF_WELL_KNOWN}.
   * @see #TNF_WELL_KNOWN
   */
  public static final byte[] RTD_URI = {0x55};   // "U"

  /**
   * RTD Smart Poster type. For use with {@literal TNF_WELL_KNOWN}.
   * @see #TNF_WELL_KNOWN
   */
  public static final byte[] RTD_SMART_POSTER = {0x53, 0x70};  // "Sp"

  /**
   * RTD Alternative Carrier type. For use with {@literal TNF_WELL_KNOWN}.
   * @see #TNF_WELL_KNOWN
   */
  public static final byte[] RTD_ALTERNATIVE_CARRIER = {0x61, 0x63};  // "ac"

  /**
   * RTD Handover Carrier type. For use with {@literal TNF_WELL_KNOWN}.
   * @see #TNF_WELL_KNOWN
   */
  public static final byte[] RTD_HANDOVER_CARRIER = {0x48, 0x63};  // "Hc"

  /**
   * RTD Handover Request type. For use with {@literal TNF_WELL_KNOWN}.
   * @see #TNF_WELL_KNOWN
   */
  public static final byte[] RTD_HANDOVER_REQUEST = {0x48, 0x72};  // "Hr"

  /**
   * RTD Handover Select type. For use with {@literal TNF_WELL_KNOWN}.
   * @see #TNF_WELL_KNOWN
   */
  public static final byte[] RTD_HANDOVER_SELECT = {0x48, 0x73}; // "Hs"

  /**
   * RTD Android app type. For use with {@literal TNF_EXTERNAL}.
   * <p>
   * The payload of a record with type RTD_ANDROID_APP
   * should be the package name identifying an application.
   * Multiple RTD_ANDROID_APP records may be included
   * in a single {@link NdefMessage}.
   * <p>
   * Use {@link #createApplicationRecord(String)} to create
   * RTD_ANDROID_APP records.
   * @hide
   */
  public static final byte[] RTD_ANDROID_APP = "android.com:pkg".getBytes();

  private static final byte FLAG_MB = (byte) 0x80;
  private static final byte FLAG_ME = (byte) 0x40;
  private static final byte FLAG_CF = (byte) 0x20;
  private static final byte FLAG_SR = (byte) 0x10;
  private static final byte FLAG_IL = (byte) 0x08;

  /**
   * NFC Forum "URI Record Type Definition"<p>
   * This is a mapping of "URI Identifier Codes" to URI string prefixes,
   * per section 3.2.2 of the NFC Forum URI Record Type Definition document.
   */
  private static final String[] URI_PREFIX_MAP = new String[] {
      "", // 0x00
      "http://www.", // 0x01
      "https://www.", // 0x02
      "http://", // 0x03
      "https://", // 0x04
      "tel:", // 0x05
      "mailto:", // 0x06
      "ftp://anonymous:anonymous@", // 0x07
      "ftp://ftp.", // 0x08
      "ftps://", // 0x09
      "sftp://", // 0x0A
      "smb://", // 0x0B
      "nfs://", // 0x0C
      "ftp://", // 0x0D
      "dav://", // 0x0E
      "news:", // 0x0F
      "telnet://", // 0x10
      "imap:", // 0x11
      "rtsp://", // 0x12
      "urn:", // 0x13
      "pop:", // 0x14
      "sip:", // 0x15
      "sips:", // 0x16
      "tftp:", // 0x17
      "btspp://", // 0x18
      "btl2cap://", // 0x19
      "btgoep://", // 0x1A
      "tcpobex://", // 0x1B
      "irdaobex://", // 0x1C
      "file://", // 0x1D
      "urn:epc:id:", // 0x1E
      "urn:epc:tag:", // 0x1F
      "urn:epc:pat:", // 0x20
      "urn:epc:raw:", // 0x21
      "urn:epc:", // 0x22
      "urn:nfc:", // 0x23
  };

  private static final int MAX_PAYLOAD_SIZE = 10 * (1 << 20);  // 10 MB payload limit

  private static final byte[] EMPTY_BYTE_ARRAY = new byte[0];
  private final short mTnf;
  private final byte[] mType;
  private final byte[] mId;
  private final byte[] mPayload;

  public static NdefRecord createApplicationRecord(String packageName) {
    if (packageName == null) throw new NullPointerException("packageName is null");
    if (packageName.length() == 0) throw new IllegalArgumentException("packageName is empty");

    return new NdefRecord(TNF_EXTERNAL_TYPE, RTD_ANDROID_APP, null,
        packageName.getBytes(StandardCharsets.UTF_8));
  }

  public static NdefRecord createUri(URI uri) {
    if (uri == null) throw new NullPointerException("uri is null");

    uri = uri.normalize();
    String uriString = uri.toString();
    if (uriString.length() == 0) throw new IllegalArgumentException("uri is empty");

    byte prefix = 0;
    for (int i = 1; i < URI_PREFIX_MAP.length; i++) {
      if (uriString.startsWith(URI_PREFIX_MAP[i])) {
        prefix = (byte) i;
        uriString = uriString.substring(URI_PREFIX_MAP[i].length());
        break;
      }
    }
    byte[] uriBytes = uriString.getBytes(StandardCharsets.UTF_8);
    byte[] recordBytes = new byte[uriBytes.length + 1];
    recordBytes[0] = prefix;
    System.arraycopy(uriBytes, 0, recordBytes, 1, uriBytes.length);
    return new NdefRecord(TNF_WELL_KNOWN, RTD_URI, null, recordBytes);
  }
  public static NdefRecord createUri(String uriString) throws URISyntaxException {
    return createUri(new URI(uriString));
  }
  public static NdefRecord createMime(String mimeType, byte[] mimeData) {
    if (mimeType == null) throw new NullPointerException("mimeType is null");

    // We only do basic MIME type validation: trying to follow the
    // RFCs strictly only ends in tears, since there are lots of MIME
    // types in common use that are not strictly valid as per RFC rules
    mimeType = normalizeMimeType(mimeType);
    if (mimeType.length() == 0) throw new IllegalArgumentException("mimeType is empty");
    int slashIndex = mimeType.indexOf('/');
    if (slashIndex == 0) throw new IllegalArgumentException("mimeType must have major type");
    if (slashIndex == mimeType.length() - 1) {
      throw new IllegalArgumentException("mimeType must have minor type");
    }
    // missing '/' is allowed

    // MIME RFCs suggest ASCII encoding for content-type
    byte[] typeBytes = mimeType.getBytes(StandardCharsets.US_ASCII);
    return new NdefRecord(TNF_MIME_MEDIA, typeBytes, null, mimeData);
  }

  public static NdefRecord createExternal(String domain, String type, byte[] data) {
    if (domain == null) throw new NullPointerException("domain is null");
    if (type == null) throw new NullPointerException("type is null");

    domain = domain.trim().toLowerCase(Locale.ROOT);
    type = type.trim().toLowerCase(Locale.ROOT);

    if (domain.length() == 0) throw new IllegalArgumentException("domain is empty");
    if (type.length() == 0) throw new IllegalArgumentException("type is empty");

    byte[] byteDomain = domain.getBytes(StandardCharsets.UTF_8);
    byte[] byteType = type.getBytes(StandardCharsets.UTF_8);
    byte[] b = new byte[byteDomain.length + 1 + byteType.length];
    System.arraycopy(byteDomain, 0, b, 0, byteDomain.length);
    b[byteDomain.length] = ':';
    System.arraycopy(byteType, 0, b, byteDomain.length + 1, byteType.length);

    return new NdefRecord(TNF_EXTERNAL_TYPE, b, null, data);
  }

  public static NdefRecord createTextRecord(String languageCode, String text) {
    if (text == null) throw new NullPointerException("text is null");

    byte[] textBytes = text.getBytes(StandardCharsets.UTF_8);

    byte[] languageCodeBytes = null;
    if (languageCode != null && !languageCode.isEmpty()) {
      languageCodeBytes = languageCode.getBytes(StandardCharsets.US_ASCII);
    } else {
      languageCodeBytes = Locale.getDefault().getLanguage().
          getBytes(StandardCharsets.US_ASCII);
    }
    // We only have 6 bits to indicate ISO/IANA language code.
    if (languageCodeBytes.length >= 64) {
      throw new IllegalArgumentException("language code is too long, must be <64 bytes.");
    }
    ByteBuffer buffer = ByteBuffer.allocate(1 + languageCodeBytes.length + textBytes.length);

    byte status = (byte) (languageCodeBytes.length & 0xFF);
    buffer.put(status);
    buffer.put(languageCodeBytes);
    buffer.put(textBytes);

    return new NdefRecord(TNF_WELL_KNOWN, RTD_TEXT, null, buffer.array());
  }

  public NdefRecord(short tnf, byte[] type, byte[] id, byte[] payload) {
    /* convert nulls */
    if (type == null) type = EMPTY_BYTE_ARRAY;
    if (id == null) id = EMPTY_BYTE_ARRAY;
    if (payload == null) payload = EMPTY_BYTE_ARRAY;

    String message = validateTnf(tnf, type, id, payload);
    if (message != null) {
      throw new IllegalArgumentException(message);
    }

    mTnf = tnf;
    mType = type;
    mId = id;
    mPayload = payload;
  }

  public short getTnf() {
    return mTnf;
  }

  public byte[] getType() {
    return mType.clone();
  }

  public byte[] getId() {
    return mId.clone();
  }

  public byte[] getPayload() {
    return mPayload.clone();
  }

  public String toMimeType() {
    switch (mTnf) {
      case NdefRecord.TNF_WELL_KNOWN:
        if (Arrays.equals(mType, NdefRecord.RTD_TEXT)) {
          return "text/plain";
        }
        break;
      case NdefRecord.TNF_MIME_MEDIA:
        String mimeType = new String(mType, StandardCharsets.US_ASCII);
        return normalizeMimeType(mimeType);
    }
    return null;
  }
  public URI toUri() {
    return toUri(false);
  }

  private URI toUri(boolean inSmartPoster) {
    switch (mTnf) {
      case TNF_WELL_KNOWN:
        if (Arrays.equals(mType, RTD_SMART_POSTER) && !inSmartPoster) {
          try {
            // check payload for a nested NDEF Message containing a URI
            NdefMessage nestedMessage = new NdefMessage(mPayload);
            for (NdefRecord nestedRecord : nestedMessage.getRecords()) {
              URI uri = nestedRecord.toUri(true);
              if (uri != null) {
                return uri;
              }
            }
          } catch (Exception e) {  }
        } else if (Arrays.equals(mType, RTD_URI)) {
          URI wktUri = parseWktUri();
          return (wktUri != null ? wktUri.normalize() : null);
        }
        break;

      case TNF_ABSOLUTE_URI:
        try {
          URI uri = new URI(new String(mType, StandardCharsets.UTF_8));
          return uri.normalize();
        }catch(Exception e) { }

      case TNF_EXTERNAL_TYPE:
        if (inSmartPoster) {
          break;
        }
        try {
          return new URI("vnd.android.nfc://ext/" + new String(mType, StandardCharsets.US_ASCII));
        }catch(Exception e) { }
    }
    return null;
  }

  public static NdefRecord[] parse(ByteBuffer buffer, boolean ignoreMbMe) throws Exception {
    List<NdefRecord> records = new ArrayList<NdefRecord>();

    try {
      byte[] type = null;
      byte[] id = null;
      byte[] payload = null;
      ArrayList<byte[]> chunks = new ArrayList<byte[]>();
      boolean inChunk = false;
      short chunkTnf = -1;
      boolean me = false;

      while (!me) {
        byte flag = buffer.get();

        boolean mb = (flag & NdefRecord.FLAG_MB) != 0;
        me = (flag & NdefRecord.FLAG_ME) != 0;
        boolean cf = (flag & NdefRecord.FLAG_CF) != 0;
        boolean sr = (flag & NdefRecord.FLAG_SR) != 0;
        boolean il = (flag & NdefRecord.FLAG_IL) != 0;
        short tnf = (short)(flag & 0x07);

        if (!mb && records.size() == 0 && !inChunk && !ignoreMbMe) {
          throw new Exception("expected MB flag");
        } else if (mb && (records.size() != 0 || inChunk) && !ignoreMbMe) {
          throw new Exception("unexpected MB flag");
        } else if (inChunk && il) {
          throw new Exception("unexpected IL flag in non-leading chunk");
        } else if (cf && me) {
          throw new Exception("unexpected ME flag in non-trailing chunk");
        } else if (inChunk && tnf != NdefRecord.TNF_UNCHANGED) {
          throw new Exception("expected TNF_UNCHANGED in non-leading chunk");
        } else if (!inChunk && tnf == NdefRecord.TNF_UNCHANGED) {
          throw new Exception("" +
              "unexpected TNF_UNCHANGED in first chunk or unchunked record");
        }

        int typeLength = buffer.get() & 0xFF;
        long payloadLength = sr ? (buffer.get() & 0xFF) : (buffer.getInt() & 0xFFFFFFFFL);
        int idLength = il ? (buffer.get() & 0xFF) : 0;

        if (inChunk && typeLength != 0) {
          throw new Exception("expected zero-length type in non-leading chunk");
        }

        if (!inChunk) {
          type = (typeLength > 0 ? new byte[typeLength] : EMPTY_BYTE_ARRAY);
          id = (idLength > 0 ? new byte[idLength] : EMPTY_BYTE_ARRAY);
          buffer.get(type);
          buffer.get(id);
        }

        ensureSanePayloadSize(payloadLength);
        payload = (payloadLength > 0 ? new byte[(int)payloadLength] : EMPTY_BYTE_ARRAY);
        buffer.get(payload);

        if (cf && !inChunk) {
          // first chunk
          if (typeLength == 0 && tnf != NdefRecord.TNF_UNKNOWN) {
            throw new Exception("expected non-zero type length in first chunk");
          }
          chunks.clear();
          chunkTnf = tnf;
        }
        if (cf || inChunk) {
          // any chunk
          chunks.add(payload);
        }
        if (!cf && inChunk) {
          // last chunk, flatten the payload
          payloadLength = 0;
          for (byte[] p : chunks) {
            payloadLength += p.length;
          }
          ensureSanePayloadSize(payloadLength);
          payload = new byte[(int)payloadLength];
          int i = 0;
          for (byte[] p : chunks) {
            System.arraycopy(p, 0, payload, i, p.length);
            i += p.length;
          }
          tnf = chunkTnf;
        }
        if (cf) {
          // more chunks to come
          inChunk = true;
          continue;
        } else {
          inChunk = false;
        }

        String error = validateTnf(tnf, type, id, payload);
        if (error != null) {
          throw new Exception(error);
        }
        records.add(new NdefRecord(tnf, type, id, payload));
        if (ignoreMbMe) {  // for parsing a single NdefRecord
          break;
        }
      }
    } catch (BufferUnderflowException e) {
      throw new Exception("expected more data", e);
    }
    return records.toArray(new NdefRecord[records.size()]);
  }

  public void writeToByteBuffer(ByteBuffer buffer, boolean mb, boolean me) {
    boolean sr = mPayload.length < 256;
    boolean il = mTnf == TNF_EMPTY ? true : mId.length > 0;

    byte flags = (byte)((mb ? FLAG_MB : 0) | (me ? FLAG_ME : 0) |
        (sr ? FLAG_SR : 0) | (il ? FLAG_IL : 0) | mTnf);
    buffer.put(flags);

    buffer.put((byte)mType.length);
    if (sr) {
      buffer.put((byte)mPayload.length);
    } else {
      buffer.putInt(mPayload.length);
    }
    if (il) {
      buffer.put((byte)mId.length);
    }

    buffer.put(mType);
    buffer.put(mId);
    buffer.put(mPayload);
  }
  private static void ensureSanePayloadSize(long size) throws Exception {
    if (size > MAX_PAYLOAD_SIZE) {
      throw new Exception(
          "payload above max limit: " + size + " > " + MAX_PAYLOAD_SIZE);
    }
  }
  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + Arrays.hashCode(mId);
    result = prime * result + Arrays.hashCode(mPayload);
    result = prime * result + mTnf;
    result = prime * result + Arrays.hashCode(mType);
    return result;
  }
  public boolean equals(@Nullable Object obj) {
    if (this == obj) return true;
    if (obj == null) return false;
    if (getClass() != obj.getClass()) return false;
    NdefRecord other = (NdefRecord) obj;
    if (!Arrays.equals(mId, other.mId)) return false;
    if (!Arrays.equals(mPayload, other.mPayload)) return false;
    if (mTnf != other.mTnf) return false;
    return Arrays.equals(mType, other.mType);
  }

  @Override
  public String toString() {
    StringBuilder b = new StringBuilder(String.format("NdefRecord tnf=%X", mTnf));
    if (mType.length > 0) b.append(" type=").append(bytesToString(mType));
    if (mId.length > 0) b.append(" id=").append(bytesToString(mId));
    if (mPayload.length > 0) b.append(" payload=").append(bytesToString(mPayload));
    return b.toString();
  }
  private static StringBuilder bytesToString(byte[] bs) {
    StringBuilder s = new StringBuilder();
    for (byte b : bs) {
      s.append(String.format("%02X", b));
    }
    return s;
  }
  int getByteLength() {
    int length = 3 + mType.length + mId.length + mPayload.length;

    boolean sr = mPayload.length < 256;
    boolean il = mTnf == TNF_EMPTY ? true : mId.length > 0;

    if (!sr) length += 3;
    if (il) length += 1;

    return length;
  }

  private URI parseWktUri() {
    if (mPayload.length < 2) {
      return null;
    }

    // payload[0] contains the URI Identifier Code, as per
    // NFC Forum "URI Record Type Definition" section 3.2.2.
    int prefixIndex = (mPayload[0] & (byte)0xFF);
    if (prefixIndex < 0 || prefixIndex >= URI_PREFIX_MAP.length) {
      return null;
    }
    String prefix = URI_PREFIX_MAP[prefixIndex];
    String suffix = new String(Arrays.copyOfRange(mPayload, 1, mPayload.length),
        StandardCharsets.UTF_8);
    try {
      return new URI(prefix + suffix);
    } catch (URISyntaxException e) {
      e.printStackTrace();
    }
    return null;
  }

  static String validateTnf(short tnf, byte[] type, byte[] id, byte[] payload) {
    switch (tnf) {
      case TNF_EMPTY:
        if (type.length != 0 || id.length != 0 || payload.length != 0) {
          return "unexpected data in TNF_EMPTY record";
        }
        return null;
      case TNF_WELL_KNOWN:
      case TNF_MIME_MEDIA:
      case TNF_ABSOLUTE_URI:
      case TNF_EXTERNAL_TYPE:
        return null;
      case TNF_UNKNOWN:
      case TNF_RESERVED:
        if (type.length != 0) {
          return "unexpected type field in TNF_UNKNOWN or TNF_RESERVEd record";
        }
        return null;
      case TNF_UNCHANGED:
        return "unexpected TNF_UNCHANGED in first chunk or logical record";
      default:
        return String.format("unexpected tnf value: 0x%02x", tnf);
    }
  }
  public static @Nullable  String normalizeMimeType(@Nullable String type) {
    if (type == null) {
      return null;
    }

    type = type.trim().toLowerCase(Locale.ROOT);

    final int semicolonIndex = type.indexOf(';');
    if (semicolonIndex != -1) {
      type = type.substring(0, semicolonIndex);
    }
    return type;
  }
}
