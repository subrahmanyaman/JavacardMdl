package com.android.javacard.mdl;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;

// TODO this is a placeholder class until design is finalized. If KeyMint applet needs to be
//  integrated then this class will be replaced by some shareable interface implemented by the
//  KeyMint applet.
public class X509CertHandler {
  public static final byte ASN1_OCTET_STRING = 0x04;
  public static final byte ASN1_SEQUENCE = 0x30;
  public static final byte ASN1_SET = 0x31;
  public static final byte ASN1_INTEGER = 0x02;
  public static final byte OBJECT_IDENTIFIER = 0x06;
  public static final byte ASN1_A0_TAG = (byte) 0xA0;
  public static final byte ASN1_A1_TAG = (byte) 0xA1;
  public static final byte ASN1_BIT_STRING = 0x03;

  public static final byte ASN1_UTF8_STRING = 0x0C;
  public static final byte ASN1_TELETEX_STRING = 0x14;
  public static final byte ASN1_PRINTABLE_STRING = 0x13;
  public static final byte ASN1_UNIVERSAL_STRING = 0x1C;
  public static final byte ASN1_BMP_STRING = 0x1E;
  public static final byte IA5_STRING = 0x16;
  private static final short KEYMINT_VERSION = 300;
  private static final byte STRONGBOX = 2;
  private static final short ATTESTATION_VERSION = 300;
  private static final short SEQUENCE_TAG = (short)0x30;

  // Android Extn - 1.3.6.1.4.1.11129.2.1.17
  private static final byte[] androidExtn = {
      0x06, 0x0A, 0X2B, 0X06, 0X01, 0X04, 0X01, (byte) 0XD6, 0X79, 0X02, 0X01, 0X11
  };
  //TODO remove this once ROT solution is clarified.
  private static final byte[] dummyROT = {
      (byte) 0xBF, (byte) 0x85, 0x40, 0x4C, 0x30, 0x4A, 0x04, 0x20,
      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
      0x01,  0x01, 0x00, 0x0A, 0x01, 0x02, 0x04, 0x20,
      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  };
  /**
   *     version [0] (1 elem)
   *       Version INTEGER 2
   *     serialNumber CertificateSerialNumber INTEGER 1
   *     signature AlgorithmIdentifier SEQUENCE (1 elem)
   *       algorithm OBJECT IDENTIFIER 1.2.840.10045.4.3.2 ecdsaWithSHA256 (ANSI X9.62 ECDSA algorithm with SHA256)
   *     issuer Name SEQUENCE (5 elem)
   *       RelativeDistinguishedName SET (1 elem)
   *         AttributeTypeAndValue SEQUENCE (2 elem)
   *           type AttributeType OBJECT IDENTIFIER 2.5.4.6 countryName (X.520 DN component)
   *           value AttributeValue PrintableString US
   *       RelativeDistinguishedName SET (1 elem)
   *         AttributeTypeAndValue SEQUENCE (2 elem)
   *           type AttributeType OBJECT IDENTIFIER 2.5.4.8 stateOrProvinceName (X.520 DN component)
   *           value AttributeValue UTF8String California
   *       RelativeDistinguishedName SET (1 elem)
   *         AttributeTypeAndValue SEQUENCE (2 elem)
   *           type AttributeType OBJECT IDENTIFIER 2.5.4.10 organizationName (X.520 DN component)
   *           value AttributeValue UTF8String Google, Inc.
   *       RelativeDistinguishedName SET (1 elem)
   *         AttributeTypeAndValue SEQUENCE (2 elem)
   *           type AttributeType OBJECT IDENTIFIER 2.5.4.11 organizationalUnitName (X.520 DN component)
   *           value AttributeValue UTF8String Android
   *       RelativeDistinguishedName SET (1 elem)
   *         AttributeTypeAndValue SEQUENCE (2 elem)
   *           type AttributeType OBJECT IDENTIFIER 2.5.4.3 commonName (X.520 DN component)
   *           value AttributeValue UTF8String Android Keystore Software Attestation Intermediate
   */
  private static final byte[] credKeyCertCommon_1 = {
      (byte)0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01, 0x30, 0x0A, 0x06, 0x08,
      0x2A, (byte)0x86, 0x48, (byte)0xCE, 0x3D, 0x04, 0x03, 0x02, 0x30, (byte)0x81, (byte)0x88, 0x31,
      0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53,
      0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0C, 0x0A, 0x43,
      0x61, 0x6C, 0x69, 0x66, 0x6F, 0x72, 0x6E, 0x69, 0x61, 0x31, 0x15, 0x30,
      0x13, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x0C, 0x0C, 0x47, 0x6F, 0x6F, 0x67,
      0x6C, 0x65, 0x2C, 0x20, 0x49, 0x6E, 0x63, 0x2E, 0x31, 0x10, 0x30, 0x0E,
      0x06, 0x03, 0x55, 0x04, 0x0B, 0x0C, 0x07, 0x41, 0x6E, 0x64, 0x72, 0x6F,
      0x69, 0x64, 0x31, 0x3B, 0x30, 0x39, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C,
      0x32, 0x41, 0x6E, 0x64, 0x72, 0x6F, 0x69, 0x64, 0x20, 0x4B, 0x65, 0x79,
      0x73, 0x74, 0x6F, 0x72, 0x65, 0x20, 0x53, 0x6F, 0x66, 0x74, 0x77, 0x61,
      0x72, 0x65, 0x20, 0x41, 0x74, 0x74, 0x65, 0x73, 0x74, 0x61, 0x74, 0x69,
      0x6F, 0x6E, 0x20, 0x49, 0x6E, 0x74, 0x65, 0x72, 0x6D, 0x65, 0x64, 0x69,
      0x61, 0x74, 0x65,
  };
  /**
   * SEQUENCE (2 elem)
   *     UTCTime 2023-04-18 18:27:29 UTC
   *     UTCTime 2026-01-08 00:46:09 UTC
   */
/*        0x30, 0x1E, 0x17, 0x0D, 0x32, 0x33, 0x30, 0x34, 0x31,
            0x38, 0x31, 0x38, 0x32, 0x37, 0x32, 0x39, 0x5A, 0x17, 0x0D, 0x32, 0x36,
            0x30, 0x31, 0x30, 0x38, 0x30, 0x30, 0x34, 0x36, 0x30, 0x39, 0x5A,
            0x30,
*/
  /**
   *     subject Name SEQUENCE (1 elem)
   *       RelativeDistinguishedName SET (1 elem)
   *         AttributeTypeAndValue SEQUENCE (2 elem)
   *           type AttributeType OBJECT IDENTIFIER 2.5.4.3 commonName (X.520 DN component)
   *           value AttributeValue UTF8String Android Identity Credential Key
   *     subjectPublicKeyInfo SubjectPublicKeyInfo SEQUENCE (2 elem)
   *       algorithm AlgorithmIdentifier SEQUENCE (2 elem)
   *         algorithm OBJECT IDENTIFIER 1.2.840.10045.2.1 ecPublicKey (ANSI X9.62 public key type)
   *         parameters ANY OBJECT IDENTIFIER 1.2.840.10045.3.1.7 prime256v1
   *                                                    (ANSI X9.62 named elliptic curve)
   *       <Add BIT STRING containing the CredKey's public_key following the above>
   */
  private static final byte[] credKeyCommonName = {
      0x30, 0x2A, 0x31, 0x28, 0x30, 0x26, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x1F,
      0x41, 0x6E, 0x64, 0x72, 0x6F, 0x69, 0x64, 0x20, 0x49, 0x64, 0x65, 0x6E,
      0x74, 0x69, 0x74, 0x79, 0x20, 0x43, 0x72, 0x65, 0x64, 0x65, 0x6E, 0x74,
      0x69, 0x61, 0x6C, 0x20, 0x4B, 0x65, 0x79,
  };
  private static final byte[] credKeyCertCommon_2 = {
      0x30, 0x13, 0x06, 0x07, 0x2A,(byte) 0x86, 0x48, (byte)0xCE, 0x3D, 0x02, 0x01,
      0x06, 0x08, 0x2A,(byte) 0x86, 0x48, (byte)0xCE, 0x3D, 0x03, 0x01, 0x07,
  };
  /**
   * signatureAlgorithm AlgorithmIdentifier SEQUENCE (1 elem)
   *     algorithm OBJECT IDENTIFIER 1.2.840.10045.4.3.2 ecdsaWithSHA256
   *                                               (ANSI X9.62 ECDSA algorithm with SHA256)
   */
  private static final byte[] credKeyCertCommon_3 = {
      0x30, 0x0A, 0x06, 0x08, 0x2A, (byte)0x86, 0x48, (byte)0xCE, 0x3D, 0x04, 0x03, 0x02,
  };
  /**
   * signatureAlgorithm AlgorithmIdentifier SEQUENCE (1 elem)
   *     algorithm OBJECT IDENTIFIER 1.2.840.10045.4.3.2 ecdsaWithSHA256
   *                                               (ANSI X9.62 ECDSA algorithm with SHA256)
   */
  private static final byte[] ecdsaWithSHA256 = {
      0x06, 0x08, 0x2A, (byte)0x86, 0x48, (byte)0xCE, 0x3D, 0x04, 0x03, 0x02,
  };
  private static final byte[] ecdsaWithSHA384 = {
      0x06, 0x08, 0x2A, (byte)0x86, 0x48, (byte)0xCE, 0x3D, 0x04, 0x03, 0x03,
  };
  private static final byte[] ecdsaWithSHA512 = {
      0x06, 0x08, 0x2A, (byte)0x86, 0x48, (byte)0xCE, 0x3D, 0x04, 0x03, 0x04,
  };
  /**
   * Key usage extension only has digitalSignature but i.e. bit 0 enabled. Rest ofr the 7 buts
   * are unused.
   * Extension SEQUENCE (3 elem)
   *           extnID OBJECT IDENTIFIER 2.5.29.15 keyUsage (X.509 extension)
   *           critical BOOLEAN true
   *           extnValue OCTET STRING (4 byte) 03020780
   *             BIT STRING (1 bit) 1
   */
  private static final byte[] keyUsage = {
      0x30, 0x0E, 0x06, 0x03, 0x55, 0x1D, 0x0F, 0x01, 0x01, (byte)0xFF, 0x04, 0x04,
      0x03, 0x02, 0x07, (byte) 0x80,
  };
  /**
   *     [1] (1 elem)
   *       SET (1 elem)
   *         INTEGER 2
   *     [2] (1 elem)
   *       INTEGER 3
   *     [3] (1 elem)
   *       INTEGER 256
   *     [5] (1 elem)
   *       SET (1 elem)
   *         INTEGER 4
   *     [10] (1 elem)
   *       INTEGER 1
   *     [503] (1 elem)
   *       NULL
   */
  private static final byte[] credKeyCertExtFixed = {
      (byte)0xA1, 0x05, 0x31, 0x03, 0x02, 0x01, 0x02, (byte)0xA2, 0x03,
      0x02, 0x01, 0x03, (byte)0xA3, 0x04, 0x02, 0x02, 0x01, 0x00,
      (byte)0xA5, 0x05, 0x31, 0x03, 0x02, 0x01, 0x04, (byte)0xAA, 0x03,
      0x02, 0x01, 0x01, (byte)0xBF, (byte)0x83, 0x77, 0x02, 0x05, 0x00,
  };
  /**
   * [1] (1 elem)
   *       SET (1 elem)
   *         INTEGER 2
   *     [2] (1 elem)
   *       INTEGER 3
   *     [3] (1 elem)
   *       INTEGER 256
   *     [5] (1 elem)
   *       SET (1 elem)
   *         INTEGER 4
   *     [10] (1 elem)
   *       INTEGER 1
   *     [503] (1 elem)
   *       NULL
   */
  static byte[] mDataStorage;
  static short mStorageIndex;
  static short mPublicKeyCertStart;
  static short mPublicKeyCertLength;
  private static ECPrivateKey mAttestKey;
  private static short[] mRetVal;

  // Following methods are used to create certificates
  private static short pushBytes(byte[] stack, short stackPtr, short stackLen,
      byte[] buf, short start, short len) {
    stackPtr -= len;
    if (buf != null) {
      Util.arrayCopyNonAtomic(buf, start, stack, stackPtr, len);
    }
    return stackPtr;
  }
  // RootOfTrust ::= SEQUENCE {
  //          verifiedBootKey            OCTET_STRING,
  //          deviceLocked               BOOLEAN,
  //          verifiedBootState          VerifiedBootState,
  //          verifiedBootHash           OCTET_STRING,
  //      }
  // VerifiedBootState ::= ENUMERATED {
  //          Verified                   (0),
  //          SelfSigned                 (1),
  //          Unverified                 (2),
  //          Failed                     (3),
  //      }
  private static short pushRoT(
      byte[] stack, short stackPtr, short stackLen) {
    /*
    short last = stackPtr;

    // verified boot hash
    stackPtr = pushOctetString(stack, stackPtr, stackLen,
        verifiedBootHash, verifiedBootHashStart, verifiedBootHashLen);

    stackPtr = pushEnumerated(stack, stackPtr, stackLen,verifiedBootState);

    stackPtr = pushBoolean(stack, stackPtr, stackLen,deviceLocked ? (byte)1 : (byte)0);
    // verified boot Key
    stackPtr = pushOctetString(stack, stackPtr, stackLen,
    verifiedBootKey,verifiedBootKeyStart, verifiedBootKeyLen);

    // Finally sequence header
    stackPtr = pushSequenceHeader(stack, stackPtr, stackLen,(short) (last - stackPtr));
    // ... and tag Id
    return pushTagIdHeader(stack, stackPtr, stackLen,(short)704, (short) (last - stackPtr));
     */
    //TODO change this once ROT params exchange mechanism is clarified.
    return pushBytes(stack,stackPtr,stackLen, dummyROT,(short)0, (short) dummyROT.length);
  }

  private static short pushIntegerTag(byte[] stack, short stackPtr, short stackLen,
      byte[] val, short valStart, short valLen, short tag){
    short lastStackPtr = stackPtr;
    stackPtr = pushInteger(stack, stackPtr, stackLen,
        val, valStart, valLen);
    return  pushTagIdHeader(stack, stackPtr, stackLen,tag,
        (short) (lastStackPtr - stackPtr));
  }
  private static short pushBooleanTag(byte[] stack, short stackPtr, short stackLen,
      byte boolVal, short tag){

    short lastStackPtr = stackPtr;
    stackPtr = pushBoolean(stack, stackPtr, stackLen, (byte)1);
    return  pushTagIdHeader(stack, stackPtr, stackLen,tag,
        (short) (lastStackPtr - stackPtr));
  }

  private static short pushOctetTag(byte[] stack, short stackPtr, short stackLen,
      byte[] val, short valStart, short valLen, short tag){
    short lastStackPtr = stackPtr;
    stackPtr = pushOctetString(stack, stackPtr, stackLen,
        val, valStart, valLen);
    return  pushTagIdHeader(stack, stackPtr, stackLen,tag,
        (short) (lastStackPtr - stackPtr));
  }

  private static short pushHwEnforcedParams(byte[] stack, short stackPtr, short stackLen,
      boolean testCredential,
      byte[] osVersion, short osVersionStart, short osVersionLen,
      byte[] osPatchLevel, short osPatchLevelStart, short osPatchLevelLen
      ){
    short lastStackPtr = stackPtr;
    // If this cert is not for test credential then add IDENTITY_CREDENTIAL tag.
    if(!testCredential){
      stackPtr = pushBooleanTag(stack, stackPtr, stackLen, (byte)1, (short)721);
    }

    // os patch level
    if(osPatchLevel != null){
      stackPtr = pushIntegerTag(stack, stackPtr, stackLen,
          osPatchLevel, osPatchLevelStart, osPatchLevelLen, (short) 706);
    }
    // os version
    if(osVersion != null){
      stackPtr = pushIntegerTag(stack, stackPtr, stackLen,
          osVersion, osVersionStart, osVersionLen, (short) 705);
    }
    // Root Of Trust
    stackPtr = pushRoT(stack, stackPtr, stackLen);

    // Finally fixed set of parameters
    stackPtr = pushBytes(stack, stackPtr, stackLen,
        credKeyCertExtFixed, (short) 0, (short) credKeyCertExtFixed.length);
    // Then sequence header for HW Params
    return pushSequenceHeader(stack, stackPtr, stackLen,
        (short) (lastStackPtr - stackPtr));
  }

  private static short pushSwEnforcedParams(byte[] stack, short stackPtr, short stackLen,
      byte[] creationDateTime, short creationDateTimeStart, short creationDateTimeLen,
      byte[] attAppId, short attAppIdStart, short attAppIdLen){
    short lastStackPtr = stackPtr;
    // attestation app id
    if(attAppId != null){
      stackPtr = pushOctetTag(stack, stackPtr, stackLen,
          attAppId, attAppIdStart, attAppIdLen, (short) 709);
    }
    if(creationDateTime != null){
      stackPtr = pushIntegerTag(stack, stackPtr, stackLen,
          creationDateTime, creationDateTimeStart, creationDateTimeLen, (short) 701);
    }
    // Then sequence header for SW Params
    stackPtr = pushSequenceHeader(stack, stackPtr, stackLen,
        (short) (lastStackPtr - stackPtr));
    return stackPtr;
  }
  // Add the extension
  private static short pushAndroidExtension(byte[] stack, short stackPtr, short stackLen,
      byte[] osVersion, short osVersionStart, short osVersionLen,
      byte[] osPatchLevel, short osPatchLevelStart, short osPatchLevelLen,
      byte[] creationDateTime, short creationDateTimeStart, short creationDateTimeLen,
      byte[] attAppId, short attAppIdStart, short attAppIdLen,
      byte[] challenge, short challengeStart, short challengeLen,
      boolean testCredential) {
    short lastStackPtr = stackPtr;
    // First hw enforced.
    stackPtr = pushHwEnforcedParams(stack, stackPtr, stackLen, testCredential,
        osVersion, osVersionStart, osVersionLen, osPatchLevel, osPatchLevelStart, osPatchLevelLen);

    // Now SW enforced
    stackPtr = pushSwEnforcedParams(stack, stackPtr, stackLen, creationDateTime,
        creationDateTimeStart, creationDateTimeLen, attAppId, attAppIdStart, attAppIdLen);
    // uniqueId is always empty.
    stackPtr = pushOctetStringHeader(stack, stackPtr, stackLen,(short) 0);
    // attest challenge
    if(challenge != null) {
      stackPtr = pushOctetString(stack, stackPtr, stackLen, challenge, challengeStart,
          challengeLen);
    }

    // Always strong box enforced
    //TODO check this out because there is no strongbox involved here - it is SE Enforced.
    stackPtr = pushEnumerated(stack, stackPtr, stackLen, (byte)2);
    stackPtr =pushShort(stack, stackPtr, stackLen,KEYMINT_VERSION);
    stackPtr =pushIntegerHeader(stack, stackPtr, stackLen,(short) 2);
    stackPtr =pushEnumerated(stack, stackPtr, stackLen,STRONGBOX);
    stackPtr =pushShort(stack, stackPtr, stackLen,ATTESTATION_VERSION);
    stackPtr =pushIntegerHeader(stack, stackPtr, stackLen,(short) 2);
    stackPtr =pushSequenceHeader(stack, stackPtr, stackLen,
        (short) (lastStackPtr - stackPtr));
    stackPtr =pushOctetStringHeader(stack, stackPtr, stackLen,(short) (lastStackPtr - stackPtr));
    stackPtr =pushBytes(stack, stackPtr, stackLen,androidExtn, (short) 0, (short) androidExtn.length);
    stackPtr = pushSequenceHeader(stack, stackPtr, stackLen,(short) (lastStackPtr - stackPtr));
    return stackPtr;
  }

  // tag id <= 30 ---> 0xA0 | {tagId}
  // 30 < tagId < 128 ---> 0xBF 0x{tagId}
  // tagId >= 128 ---> 0xBF 0x80+(tagId/128) 0x{tagId - (128*(tagId/128))}
  private static short pushTagIdHeader(byte[] stack, short stackPtr, short stackLen,short tagId,
      short len) {
    stackPtr = pushLength(stack, stackPtr, stackLen,len);
    short count = (short) (tagId / 128);
    if (count > 0) {
      stackPtr =pushByte(stack, stackPtr, stackLen,(byte) (tagId - (128 * count)));
      stackPtr =pushByte(stack, stackPtr, stackLen,(byte) (0x80 + count));
      return pushByte(stack, stackPtr, stackLen,(byte) 0xBF);
    } else if (tagId > 30) {
      stackPtr =pushByte(stack, stackPtr, stackLen,(byte) tagId);
      return pushByte(stack, stackPtr, stackLen,(byte) 0xBF);
    } else {
      return pushByte(stack, stackPtr, stackLen,(byte) (0xA0 | (byte) tagId));
    }
  }
  // Ignore leading zeros. Only Unsigned Integers are required hence if MSB is set then add 0x00
  // as most significant byte.
  private static short pushInteger(byte[] stack, short stackPtr, short stackLen, byte[] buf,
      short start, short len) {
    short last = stackPtr;
    byte index = 0;
    while (index < (byte) len) {
      if (buf[(short) (start + index)] != 0) {
        break;
      }
      index++;
    }
    if (index == (byte) len) {
      stackPtr = pushByte(stack, stackPtr, stackLen,(byte) 0x00);
    } else {
      stackPtr = pushBytes(stack, stackPtr, stackLen, buf, (short) (start + index),
          (short) (len - index));
      if (buf[(short) (start + index)] < 0) { // MSB is 1
        stackPtr = pushByte(stack, stackPtr, stackLen, (byte) 0x00); // always unsigned int
      }
    }
    return pushIntegerHeader(stack, stackPtr, stackLen,(short) (last - stackPtr));
  }
  private static short pushIntegerHeader(byte[] stack, short stackPtr, short stackLen,short len) {
    stackPtr = pushLength(stack, stackPtr, stackLen, len);
    return pushByte(stack, stackPtr, stackLen, (byte) 0x02);
  }

  private static short pushOctetStringHeader(byte[] stack, short stackPtr, short stackLen,
      short len) {
    stackPtr = pushLength(stack, stackPtr, stackLen, len);
    return pushByte(stack, stackPtr, stackLen,(byte) 0x04);
  }

  private static short pushSequenceHeader(byte[] stack, short stackPtr, short stackLen, short len) {
    stackPtr = pushLength(stack, stackPtr, stackLen, len);
    return pushByte(stack, stackPtr, stackLen, (byte) 0x30);
  }

  private static short pushBitStringHeader(byte[] stack, short stackPtr, short stackLen,
      byte unusedBits, short len) {
    stackPtr = pushByte(stack, stackPtr, stackLen, unusedBits);
    stackPtr = pushLength(stack, stackPtr, stackLen,(short) (len + 1)); // 1 extra byte for
    // unused bits byte
    return pushByte(stack, stackPtr, stackLen,(byte) 0x03);
  }

  private static short pushLength(byte[] stack, short stackPtr, short stackLen,short len) {
    if (len < 128) {
      return pushByte(stack, stackPtr, stackLen,(byte) len);
    } else if (len < 256) {
      stackPtr = pushByte(stack, stackPtr, stackLen,(byte) len);
      return pushByte(stack, stackPtr, stackLen,(byte) 0x81);
    } else {
      stackPtr = pushShort(stack, stackPtr, stackLen,len);
      return pushByte(stack, stackPtr, stackLen,(byte) 0x82);
    }
  }
  private static short pushOctetString(byte[] stack, short stackPtr, short stackLen,
      byte[] buf, short start, short len) {
    stackPtr = pushBytes(stack, stackPtr, stackLen,buf, start, len);
    return pushOctetStringHeader(stack, stackPtr, stackLen,len);
  }
  private static short pushEnumerated(byte[] stack, short stackPtr, short stackLen,
      byte val) {
    short last = stackPtr;
    stackPtr = pushByte(stack, stackPtr, stackLen,val);
    return pushEnumeratedHeader(stack, stackPtr, stackLen,(short) (last - stackPtr));
  }

  private static short pushEnumeratedHeader(byte[] stack, short stackPtr, short stackLen,
      short len) {
    stackPtr = pushLength(stack, stackPtr, stackLen,len);
    return pushByte(stack, stackPtr, stackLen,(byte) 0x0A);
  }
  private static short pushBoolean(byte[] stack, short stackPtr, short stackLen,byte val) {
    stackPtr = pushByte(stack, stackPtr, stackLen,val);
    return pushBooleanHeader(stack, stackPtr, stackLen,(short) 1);
  }

  private static short pushBooleanHeader(byte[] stack, short stackPtr, short stackLen,short len) {
    stackPtr = pushLength(stack, stackPtr, stackLen,len);
    return pushByte(stack, stackPtr, stackLen,(byte) 0x01);
  }
  private static short pushShort(byte[] stack, short stackPtr, short stackLen, short val) {
    stackPtr -= 2;
    Util.setShort(stack, stackPtr, val);
    return stackPtr;
  }

  private static short pushByte(byte[] stack, short stackPtr, short stackLen, byte val) {
    stackPtr--;
    stack[stackPtr] = val;
    return stackPtr;
  }
  // KeyDescription ::= SEQUENCE {
  //         attestationVersion         INTEGER, # Value 200
  //         attestationSecurityLevel   SecurityLevel, # See below
  //         keymasterVersion           INTEGER, # Value 200
  //         keymasterSecurityLevel     SecurityLevel, # See below
  //         attestationChallenge       OCTET_STRING, # Tag::ATTESTATION_CHALLENGE from attestParams
  //         uniqueId                   OCTET_STRING, # Empty unless key has Tag::INCLUDE_UNIQUE_ID
  //         softwareEnforced           AuthorizationList, # See below
  //         hardwareEnforced           AuthorizationList, # See below
  //     }

  private static short pushExtensions(byte[] stack, short stackPtr, short stackLen,
      byte[] osVersion, short osVersionStart, short osVersionLen,
      byte[] osPatchLevel, short osPatchLevelStart, short osPatchLevelLen,
      byte[] creationDateTime, short creationDateTimeStart, short creationDateTimeLen,
      byte[] attAppId, short attAppIdStart, short attAppIdLen,
      boolean testCredential,
      byte[] challenge, short challengeStart, short challengeLen) {
    short lastStackPtr = stackPtr;
    stackPtr = pushAndroidExtension(stack, stackPtr, stackLen,
        osVersion, osVersionStart, osVersionLen,
        osPatchLevel, osPatchLevelStart, osPatchLevelLen,
        creationDateTime, creationDateTimeStart, creationDateTimeLen,
        attAppId, attAppIdStart, attAppIdLen,
        challenge, challengeStart, challengeLen,
        testCredential);
    // Push KeyUsage extension - the key usage is always the same i.e. sign
    stackPtr = pushBytes(stack, stackPtr, stackLen, keyUsage, (short) 0, (short) keyUsage.length);
    // Now push sequence header for the Extensions
    stackPtr = pushSequenceHeader(stack, stackPtr, stackLen,
        (short) (lastStackPtr - stackPtr));
    // Extensions have explicit tag of [3]
    stackPtr = pushLength(stack, stackPtr, stackLen, (short) (lastStackPtr - stackPtr));
    stackPtr = pushByte(stack, stackPtr, stackLen, (byte) 0xA3);
    return stackPtr;
  }
  private static short pushPubKey(byte[] stack, short stackPtr, short stackLen, ECPublicKey credPubKey,
      byte[] scratch, short scratchStart){
    short lastStackPtr = stackPtr;
    short keyLen = credPubKey.getW(scratch, scratchStart);
    stackPtr = pushBytes(stack, stackPtr, stackLen, scratch, scratchStart, keyLen);
    stackPtr = pushBitStringHeader(stack, stackPtr, stackLen, (byte) 0x00, keyLen);
    // push common part 2
    stackPtr = pushBytes(stack, stackPtr, stackLen, credKeyCertCommon_2, (short)0,
        (short) credKeyCertCommon_2.length);
    stackPtr = pushSequenceHeader(stack, stackPtr, stackLen,(short) (lastStackPtr -stackPtr));
    return stackPtr;
  }
  private static short pushValidity(byte[] stack, short stackPtr, short stackLen,
      byte[] notBefore, short notBeforeStart, short notBeforeLen,
      byte[] notAfter, short notAfterStart, short notAfterLen
      ){
    short lastStackPtr = stackPtr;
    stackPtr = pushBytes(stack, stackPtr, stackLen, notAfter, notAfterStart, notAfterLen);
    stackPtr = pushBytes(stack, stackPtr, stackLen, notBefore, notBeforeStart, notBeforeLen);
    stackPtr = pushSequenceHeader(stack, stackPtr, stackLen, (short)(lastStackPtr -stackPtr));
    return stackPtr;
  }
  public static short generateCredKeyCert(ECPublicKey credPubKey,
      byte[] osVersion, short osVersionStart, short osVersionLen,
      byte[] osPatchLevel, short osPatchLevelStart, short osPatchLevelLen,
      byte[] challenge, short challengeStart, short challengeLen,
      byte[] notBefore, short notBeforeStart, short notBeforeLen,
      byte[] notAfter, short notAfterStart, short notAfterLen,
      byte[] creationDateTime, short creationDateTimeStart, short creationDateTimeLen,
      byte[] attAppId, short attAppIdStart, short attAppIdLen, boolean testCredential,
      byte[] buf, short start, short len,
      byte[] scratch, short scratchStart, short scratchLen){
    short stackPtr = len;
    // reserve space signature place-holder - 74 bytes (ASN.1 encode sequence of two integers,
    // each one 32 bytes long) + 3 bytes for bit string.
    stackPtr -= 74;
    short signatureOffset = stackPtr;
    // push common part 3.
    stackPtr = pushBytes(buf, stackPtr, len, credKeyCertCommon_3, (short)0,
        (short) credKeyCertCommon_3.length);
    short tbsEnd = stackPtr;
    // push extension
    stackPtr = pushExtensions(buf, stackPtr, (short) (len - start),
        osVersion, osVersionStart, osVersionLen,
        osPatchLevel, osPatchLevelStart, osPatchLevelLen,
        creationDateTime, creationDateTimeStart, creationDateTimeLen,
        attAppId, attAppIdStart, attAppIdLen, testCredential,
        challenge,challengeStart, challengeLen);
    //push pubkey
    stackPtr = pushPubKey(buf, stackPtr, len, credPubKey, scratch, scratchStart);
    // push common name
    stackPtr = pushBytes(buf, stackPtr, len, credKeyCommonName, (short) 0,
        (short) credKeyCommonName.length);
    //push validity period
    stackPtr = pushValidity(buf, stackPtr, len, notBefore, notBeforeStart, notBeforeLen, notAfter,
        notAfterStart, notAfterLen);
    //push common part 1
    stackPtr = pushBytes(buf, stackPtr, len, credKeyCertCommon_1, (short)0,
        (short) credKeyCertCommon_1.length);
    // push tbs header
    short tbsStart = pushSequenceHeader(buf, stackPtr, len, (short) (tbsEnd - stackPtr));
    // sign the tbs - this is ASN.1 encoded sequence of two integers.
    short signLen = SEProvider.ecSign256(mAttestKey,
        buf,tbsStart,(short) (tbsEnd-tbsStart),scratch,
        (short) 0);
    // now push signature
    short certEnd = stackPtr = (short) (signatureOffset + signLen + 3);
    stackPtr = pushBytes(buf, stackPtr, len,scratch,(short)0, signLen);
    stackPtr = pushBitStringHeader(buf, stackPtr,len,(byte) 0, signLen);
    if(stackPtr != signatureOffset){
      ISOException.throwIt(ISO7816.SW_UNKNOWN);
    }
    // add the main header which is sequence header
    stackPtr = tbsStart;
    stackPtr =  pushSequenceHeader(buf,stackPtr,len,(short)(certEnd - tbsStart));
    if(stackPtr < start){
      ISOException.throwIt(ISO7816.SW_UNKNOWN);
    }
    if(stackPtr > start) {
      Util.arrayCopyNonAtomic(buf, stackPtr, buf, start, (short) (certEnd - stackPtr));
    }
    return (short)(certEnd - stackPtr);
  }

  public static void clearAttestationKey(){
    if(mDataStorage == null) return;
    Util.arrayFillNonAtomic(
        mDataStorage, (short) 0, (short) mDataStorage.length, (byte) 0);
    mStorageIndex = 0;
  }

  public static void init(short size){
    mDataStorage = new byte[size];
    mAttestKey = (ECPrivateKey) KeyBuilder
        .buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false);
    mPublicKeyCertLength = mPublicKeyCertStart = mStorageIndex = 0;
    mRetVal = JCSystem.makeTransientShortArray((short)16, JCSystem.CLEAR_ON_DESELECT);
  }

  public static void storeAttestationPublicKeyCert(byte[] buf, short start, short len){
    if(mDataStorage == null) return;
    mPublicKeyCertStart = mStorageIndex;
    mPublicKeyCertLength = len;
    mStorageIndex = Util.arrayCopyNonAtomic(buf, start, mDataStorage, mStorageIndex, len);
  }

  public static void storeAttestationPrivateKey(byte[] buf, short start, short len){
    if(mDataStorage == null || mAttestKey == null) return;
    mAttestKey.setS(buf, start, len);

  }

  /**
   *
   *   SEQUENCE (7 elem)
   *     [0] (1 elem)
   *       INTEGER 2
   *     INTEGER 1
   *     SEQUENCE (1 elem)
   *       OBJECT IDENTIFIER 1.2.840.10045.4.3.2 ecdsaWithSHA256 (ANSI X9.62 ECDSA algorithm with SHA256)
   *     SEQUENCE (1 elem)
   *       SET (1 elem)
   *         SEQUENCE (2 elem)
   *           OBJECT IDENTIFIER 2.5.4.3 commonName (X.520 DN component)
   * Offset: 33
   * Length: 2+3
   * Value:
   * 2.5.4.3
   * commonName
   * X.520 DN component
   *           UTF8String Android Identity Credential Key
   */
  private static final byte[] certSigningKeyCommon_1 = {
      (byte)0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01, 0x30,
      0x0A, 0x06, 0x08, 0x2A, (byte)0x86, 0x48, (byte)0xCE, 0x3D, 0x04, 0x03, 0x02, 0x30,
      0x2A, 0x31, 0x28, 0x30, 0x26, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x1F,
      0x41, 0x6E, 0x64, 0x72, 0x6F, 0x69, 0x64, 0x20, 0x49, 0x64, 0x65, 0x6E,
      0x74, 0x69, 0x74, 0x79, 0x20, 0x43, 0x72, 0x65, 0x64, 0x65, 0x6E, 0x74,
      0x69, 0x61, 0x6C, 0x20, 0x4B, 0x65, 0x79,
  };

  /**
   *
   * SEQUENCE (1 elem)
   *       SET (1 elem)
   *         SEQUENCE (2 elem)
   *           OBJECT IDENTIFIER 2.5.4.3 commonName (X.520 DN component)
   *           X.520 DN component UTF8String Android Identity Credential Authentication Key
   *     SEQUENCE (2 elem)
   *       SEQUENCE (2 elem)
   *         OBJECT IDENTIFIER 1.2.840.10045.2.1 ecPublicKey (ANSI X9.62 public key type)
   *         OBJECT IDENTIFIER 1.2.840.10045.3.1.7 prime256v1 (ANSI X9.62 named elliptic curve)
   *       <followed by BIT STRING containing the public key>
   */

  private static final byte[] certSigningKeyCommon_2 = {
      0x30, 0x39, 0x31, 0x37, 0x30, 0x35, 0x06, 0x03, 0x55,
      0x04, 0x03, 0x0C, 0x2E, 0x41, 0x6E, 0x64, 0x72, 0x6F,
      0x69, 0x64, 0x20, 0x49, 0x64, 0x65, 0x6E,
      0x74, 0x69, 0x74, 0x79, 0x20, 0x43, 0x72, 0x65,  0x64,
      0x65, 0x6E, 0x74, 0x69, 0x61, 0x6C, 0x20,
      0x41, 0x75, 0x74, 0x68, 0x65, 0x6E, 0x74, 0x69,  0x63,
      0x61, 0x74, 0x69, 0x6F, 0x6E, 0x20, 0x4B,
      0x65, 0x79, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07,  0x2A,
      (byte)0x86, 0x48, (byte)0xCE, 0x3D, 0x02, 0x01, 0x06,
      0x08, 0x2A, (byte)0x86, 0x48, (byte)0xCE, 0x3D, 0x03, 0x01,  0x07,
  };
  private static final byte[] signingKey_common_name = {
      0x30, 0x39, 0x31, 0x37, 0x30, 0x35, 0x06, 0x03,
      0x55, 0x04, 0x03, 0x0C, 0x2E, 0x41, 0x6E, 0x64,
      0x72, 0x6F, 0x69, 0x64, 0x20, 0x49, 0x64, 0x65,
      0x6E, 0x74, 0x69, 0x74, 0x79, 0x20, 0x43, 0x72,
      0x65, 0x64, 0x65, 0x6E, 0x74, 0x69, 0x61, 0x6C,
      0x20, 0x41, 0x75, 0x74, 0x68, 0x65, 0x6E, 0x74,
      0x69, 0x63, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x20,
      0x4B, 0x65, 0x79
  };
  /**
   * SEQUENCE (1 elem)
   *     OBJECT IDENTIFIER 1.2.840.10045.4.3.2 ecdsaWithSHA256 (ANSI X9.62 ECDSA algorithm with SHA256)
    */
  private static final byte[] certSigningKeyCommon_3 = {
      0x30, 0x0A, 0x06,
      0x08, 0x2A, (byte)0x86, 0x48, (byte)0xCE, 0x3D, 0x04, 0x03,  0x02,
  };

  public static short generateSigningKeyCert(ECPublicKey signingPubKey, ECPrivateKey attestKey,
      byte[] notBefore, short notBeforeStart, short notBeforeLen,
      byte[] notAfter, short notAfterStart, short notAfterLen,
      byte[] buf, short start, short len,
      byte[] scratch, short scratchStart, short scratchLen) {

    short stackPtr = (short) (start + len);
    // reserve space signature place-holder - 74 bytes (ASN.1 encode sequence of two integers,
    // each one 32 bytes long) + 3 bytes for bit string.
    stackPtr -= 74;
    short signatureOffset = stackPtr;
    // push common part 3.
    stackPtr = pushBytes(buf, stackPtr, len, certSigningKeyCommon_3, (short)0,
        (short) certSigningKeyCommon_3.length);
    short tbsEnd = stackPtr;

    //push pubkey
    stackPtr = pushPubKey(buf, stackPtr, len, signingPubKey, scratch, scratchStart);

    // push common name
    stackPtr = pushBytes(buf, stackPtr, len, signingKey_common_name, (short) 0,
        (short) signingKey_common_name.length);

    //push validity period
    stackPtr = pushValidity(buf, stackPtr, len, notBefore, notBeforeStart, notBeforeLen, notAfter,
        notAfterStart, notAfterLen);

    //push common part 1
    stackPtr = pushBytes(buf, stackPtr, len, certSigningKeyCommon_1, (short)0,
        (short) certSigningKeyCommon_1.length);

    // push tbs header
    short tbsStart = pushSequenceHeader(buf, stackPtr, len, (short) (tbsEnd - stackPtr));
    // sign the tbs - this is ASN.1 encoded sequence of two integers.
    short signLen = SEProvider.ecSign256(attestKey,buf,tbsStart,(short) (tbsEnd-tbsStart),scratch,
        (short) 0);
    // now push signature
    short certEnd = stackPtr = (short) (signatureOffset + signLen + 3);
    stackPtr = pushBytes(buf, stackPtr, len,scratch,(short)0, signLen);
    stackPtr = pushBitStringHeader(buf, stackPtr,len,(byte) 0, signLen);
    if(stackPtr != signatureOffset){
      ISOException.throwIt(ISO7816.SW_UNKNOWN);
    }
    // add the main header which is sequence header
    stackPtr = tbsStart;
    stackPtr =  pushSequenceHeader(buf,stackPtr,len,(short)(certEnd - tbsStart));
    if(stackPtr < start){
      ISOException.throwIt(ISO7816.SW_UNKNOWN);
    }
    if(stackPtr > start) {
      Util.arrayCopyNonAtomic(buf, stackPtr, buf, start, (short) (certEnd - stackPtr));
    }
    return (short)(certEnd - stackPtr);

  }

  private static boolean matchAlg(byte[] buf, short start, short length, short alg){
    byte[] dest = null;
    switch(alg) {
      case MdlSpecifications.ES256:
        dest = ecdsaWithSHA256;
        break;
      case MdlSpecifications.ES384:
        dest = ecdsaWithSHA384;
        break;
      case MdlSpecifications.ES512:
        dest = ecdsaWithSHA512;
        break;
      default:
        return false;
    }
    SEProvider.print(buf, start, length);
    SEProvider.print(dest, (short) 0, length);
    return length == (short)dest.length &&
        (Util.arrayCompare(buf,start,dest,(short)0, (short)dest.length) == (short)0);
  }



  /**
   * The following method does basic chain validation.
   * 1) Extract tbs, keys, alg, signature from the chain. Also, check whether the last cert in
   * the chain is self signed.
   * 2) Check that alg requested in argument is supported by the key in the first certificate.
   * 3) Then do the chain validation if there are more than one certificate
   *
   * TODO currently key usage validation is not done and also the root cert in the chain is not
   *  validated as it is not clear whether the root cert will be self signed and if so whether it
   *  needs to be validated or not.

   */
  public static boolean validateChain(MdocPresentationPkg doc,
      byte[] buf, short[] tmpArray,
      byte[] scratch, short scratchStart, short scratchLen) {
    // store the alg
    short alg = tmpArray[0];
    // store the cert count
    short count = tmpArray[1];
    if(count <= 0) return false;
    // point to the end of the chain i.e. root cert
    short i = (short) ((short)(count * 2) + 2);
    short attKeyStart = -1;
    short attKeyLen = -1;
    boolean foundAtLeastOneKey = false;
    while(i > 2){
      short certStart = tmpArray[--i];
      short certLen = tmpArray[--i];
      SEProvider.print(buf, certStart, certLen);
      short certEnd = (short) (certStart + certLen);
      // Now decode cert - this will return 4 parameters of the cert in mRetVal
      decodeCert(buf, certStart, certEnd, mRetVal,
          scratch,scratchStart,scratchLen);

      if(doc.isMatchingReaderAuthKey(buf, mRetVal[5], mRetVal[6])){
        foundAtLeastOneKey = true;
      }
      if(count > 1 && attKeyLen > 0 &&
          !SEProvider.instance().validateEcDsaSign(buf,
          mRetVal[1], mRetVal[2], // tbs
          mRetVal[0], // alg
          scratch, mRetVal[3], mRetVal[4], // sign
          attKeyStart, attKeyLen // attestation key
      )){
        return false;
      }
      attKeyStart = mRetVal[5];
      attKeyLen = mRetVal[6];
    }
    tmpArray[0] = attKeyLen;
    tmpArray[1] = attKeyStart;
    return foundAtLeastOneKey && alg == mRetVal[0];
  }

  private static short mapAlg(short alg){
    switch(alg){
      case MdlSpecifications.ES256:
          return SEProvider.ES256;
      case MdlSpecifications.ES384:
        return SEProvider.ES384;
      case MdlSpecifications.ES512:
        return SEProvider.ES512;
    }
    return -1;
  }

  private static short readPublicKey(byte[] buf, short tbsStart, short tbsLen, short[] retVal) {
    // public key is 7th field in the tbs cert
    short tbsEnd = getNextTag(buf, tbsStart, tbsLen, retVal);
    // go inside tbs skip till 7th field
    short end = retVal[3]; //getNextTag(buf, retVal[3], retVal[2], retVal);
    for(short i = 0; i < (short) 7;i++){
      end = getNextTag(buf, end, tbsEnd, retVal);
    }
    // At this stage - retVal[0] points to Sequence start and retVal[3] points to ecPublicKey
    // sequence.
    short pubKeyEnd = end;
    short pubKeyStart = retVal[0];
    // Go inside the sequence of oid and alg
    end = getNextTag(buf, retVal[3], end, retVal);
    short keyBitStringStart = end;
    // The first element in the sequence should be OID ecPublicKey
    end = getNextTag(buf, retVal[3], end, retVal);
    short len = (short) (end - retVal[0]);
    if(len != (short) ecPublicKey.length || Util.arrayCompare(buf, retVal[0], ecPublicKey,(short)0,
        len) != 0){
      return -1;
    }
    // Now read the bit string. The value will be Bit string will start with byte which counts
    // unused bits. This will always be zero in case of EC 256, 384 and 512 keys.
    end = getNextTag(buf, keyBitStringStart, pubKeyEnd, retVal);

    if(buf[retVal[3]] != 0){
      return -1;
    }
    // skip the first byte
    pubKeyStart = (short) (retVal[3] + 1);
    pubKeyEnd = end;
    retVal[0] = pubKeyStart;

    return (short) (pubKeyEnd - pubKeyStart);
  }

  private final static byte[] ecPublicKey = {
      0x06, 0x07, 0x2A, (byte)0x86, 0x48, (byte)0xCE, 0x3D, 0x02, 0x01,};


  private static short mapAlg(byte[] buf, short start, short len){
    if(matchAlg(buf, start, len, MdlSpecifications.ES256)){
      return SEProvider.ES256;
    }else if(matchAlg(buf, start, len, MdlSpecifications.ES384)){
      return SEProvider.ES384;
    } else if(matchAlg(buf, start, len, MdlSpecifications.ES512)){
      return SEProvider.ES512;
    }else{
      return -1;
    }
  }

  /**
   *     retValues[0] = tagStart;
   *     retValues[1] = tag;
   *     retValues[2] = tagLen;
   *     retValues[3] = tagValIndex;
   */
  private static short readSign(byte[] buf, short start, short end, short[] retVal,
      byte[] scratch, short scratchStart, short scratchLen){
    // Now read next tag
    getNextTag(buf, start, (short)(end - start), retVal);
    if(retVal[1] != ASN1_BIT_STRING){
      return -1;
    }
    // first byte in the bit string should be zero in case of ecDSA signature as there should not
    // be any unused bytes.
    if(buf[retVal[3]] != 0){
      return -1;
    }
    // skip one byte and decrement tag length by one.
    retVal[3]++;
    retVal[2]--;
    short sign_end = getNextTag(buf, retVal[3], retVal[2], retVal);
    short sign_start = retVal[0];
    if(retVal[1] != ASN1_SEQUENCE){
      return -1;
    }
    short sign_s_start = getNextTag(buf, retVal[3], retVal[2], retVal);
    if(retVal[1] != ASN1_INTEGER){
      return -1;
    }
    short sign_r_start = retVal[3];
    short sign_r_len = retVal[2];
    // As the signature is encoded as positive integer - the first byte may be 00. Remove that.
    if(buf[sign_r_start] == 0){
      sign_r_start++;
      sign_r_len--;
    }
    getNextTag(buf, sign_s_start, sign_end, retVal);
    if(retVal[1] != ASN1_INTEGER){
      return -1;
    }
    sign_s_start = retVal[3];
    short sign_s_len = retVal[2];
    // As the signature is encoded as positive integer - the first byte may be 00. Remove that.
    if(buf[sign_s_start] == 0){
      sign_s_start++;
      sign_s_len--;
    }

    short index = Util.arrayCopyNonAtomic(buf, sign_r_start, scratch, scratchStart, sign_r_len);
    index = Util.arrayCopyNonAtomic(buf, sign_s_start, scratch, index, sign_s_len);
    SEProvider.print(scratch, scratchStart, (short) (index - scratchStart));
    return (short) (index - scratchStart);
  }
  private static short readAlg(byte[] buf, short start, short end, short[] retVal){
    short len = (short)(end - start);

    // Now read next tag
    short index = getNextTag(buf, start, len, retVal);
    SEProvider.print(buf, start, (short) (index - start));
    if(retVal[1] != ASN1_SEQUENCE){
      return -1;
    }
    // Compare with alg
    retVal[1] = mapAlg(buf,retVal[3], retVal[2]);
    return index;
  }
  private static short readTbs(byte[] buf, short start, short end, short[] retVal){
    short len = (short)(end - start);
    getNextTag(buf, start, len ,retVal);
    if(retVal[1] != ASN1_SEQUENCE){
      return -1;
    }
    // Go inside the sequence and read tbs
    short index = getNextTag(buf, retVal[3], retVal[2],retVal);
    if(retVal[1] != ASN1_SEQUENCE){
      return -1;
    }
    return index;
  }
  private static boolean decodeCert(byte[] buf, short certStart, short certEnd, short[] retVal,
      byte[] scratch, short scratchStart, short scratchLen){
    short tbsEnd = readTbs(buf, certStart, certEnd, retVal);
    if(tbsEnd < 0) return false;
    short tbsStart = retVal[0];
    short algEnd = readAlg(buf, tbsEnd, certEnd, retVal);
    if(algEnd < 0) return false;
    short alg = retVal[1];
    short signLen = readSign(buf, algEnd , certEnd, retVal,
        scratch, scratchStart, scratchLen);
    short signStart = scratchStart;
    short publicKeyLen = readPublicKey(buf, tbsStart, tbsEnd, retVal);
    short publicKeyStart = retVal[0];
    retVal[0] = alg;
    retVal[1] = tbsStart;
    retVal[2] = (short) (tbsEnd - tbsStart);
    retVal[3] = signStart;
    retVal[4] = signLen;
    retVal[5] = publicKeyStart;
    retVal[6] = publicKeyLen;
    return true;
  }

  /**
   * Read Tag id from the BER TLV object. In FiraApplet the tag id will only be one or two bytes long.
   * if the tag id is more than 2 bytes then ISO7816.SW_WRONG_DATA exception is thrown.
   * @param buf - buffer of data
   * @param index - start index
   * @param len - length of the buffer
   * @param retValues - The retValues[0] will return tag.
   * @return index pointing at the length field of the TLV object.
   */
  public static short readBERTag(byte[] buf, short index, short len, short[] retValues){
    if(len == 0) return (short)-1;
    if ((buf[index] & 0x1F) != 0x1F) { // 1 byte tag
      retValues[0] = (short)(buf[index] & 0x00FF);
    } else if ((buf[(short) (index + 1)] & 0x80) == 0) { //2 bytes
      retValues[0]= javacard.framework.Util.getShort(buf, index);
      index++;
    } else { // more than 2 bytes
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }
    index++;
    return index;
  }
  /**
   * Read Tag length from the BER TLV object. In FiraApplet the tag length will at maximum will be
   * 2 bytes long i.e. 32K. if the tag length is more than 2 bytes then ISO7816.SW_WRONG_LENGTH
   * exception is thrown.
   * @param buf - buffer of data
   * @param index - start index
   * @param len - length of the buffer
   * @param retValues - The retValues[0] will return tag length.
   * @return index pointing at start of the value field of the TLV object.
   */
  public static short readBERLength(byte[] buf, short index, short len, short[] retValues){
    retValues[0] = (short)-1;
    if(len == 0) return (short)-1;
    // If length is negative then there is n bytes of length ahead.
    // If length is positive then length is between 0 - 127.
    if (buf[index] < 0) {
      byte numBytes = (byte) (buf[index] & 0x7F);
      if (numBytes == 2) {
        index++;
        retValues[0] = Util.getShort(buf, index);
        index++;
      } else if (numBytes == 1) {
        index++;
        retValues[0] = (short)(buf[index] & 0x00FF);
      }else{
        ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
      }
    } else {
      retValues[0] = (short)(buf[index] & 0x00FF);
    }
    index++;
    return index;
  }
  /**
   * Read the BER TLV object pointed by index. If TLV object is larger than the len of the buffer
   * then ISO7816.SW_WRONG_LENGTH exception is thrown.
   * @param buf - buffer of data
   * @param index - start index
   * @param len - length of the buffer
   * @param retValues The returned data of the TLV object.
   *  - retValues[0] - start index of TLV object
   *  - retValues[1] - tag id.
   *  - retValues[2] - tag length
   *  - retValues[3] = start index of TLV value field.
   * @return index pointing at start of the next byte following the end of TLV object.
   */
  public static short getNextTag(byte[] buf, short index, short len, short[] retValues){
    if(len == 0) return (short)-1;
    retValues[0] = retValues[1]= retValues[2]=retValues[3]=0;
    short end = (short)(index + len);
    short tagStart = index;
    short tag;
    short tagLen;
    short tagValIndex;
    if(len == 0) return index;
    if(len < 0){
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    index = readBERTag(buf, index, len, retValues);
    tag = retValues[0];
    index = readBERLength(buf, index, len, retValues);
    tagLen = retValues[0];
    tagValIndex = index;
    index += tagLen;
    if(index > end) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    retValues[0] = tagStart;
    retValues[1] = tag;
    retValues[2] = tagLen;
    retValues[3] = tagValIndex;
    return index;
  }
  /**
   * Read the BER TLV object pointed by index and matching the tag in the buffer. If TLV object is
   * larger than the len of the buffer then ISO7816.SW_WRONG_LENGTH exception is thrown.
   * @param tag - desired tag id
   * @param buf - buffer of data
   * @param index - start index
   * @param len - length of the buffer
   * @param skip - if true then skip the receding 0xFFs and 0s.
   * @param retValues The returned data of the TLV object.
   *  - retValues[0] - start index of TLV object
   *  - retValues[1] - tag id.
   *  - retValues[2] - tag length
   *  - retValues[3] = start index of TLV value field.
   * @return index pointing at start of the next byte following the end of the desired TLV object.
   * If the tag is not present in the buffer than the FIRASpecs.INVALID_VALUE is returned
   */
  public static short getTag(short tag, byte[] buf, short index, short len, boolean skip,
      short[] retValues){
    if(len == 0) return (short)-1;
    short end = (short)(index + len);
    while(index < end){
      index = getNextTag(buf, index, (short)(end - index), retValues);
      if(retValues[1] == tag){
        return index;
      }
    }
    return (short)-1;
  }
  public static short traverseChain(short parentTag, short tag, byte[] val, short valStart,
      short valLen,
      byte[] mem, short index, short len, short[] retValues) {
    short end = (short) (index + len); // end of the credentials.
    // Read the key sets one by one - index points to beginning of the key set and the end points to
    // end of all the key sets.
    SEProvider.print(mem,index,len);
    while ( index != (short)-1 && index < end) {
      // read the tag
      index = getNextTag(mem, index, (short)(end - index),  retValues);
      // Is the tag parent tag or any tag.
      if (index != (short)-1 &&
          (parentTag == (short)-1 || parentTag == retValues[1])) {
        short curParentStart = retValues[0];
        short curParentTag = retValues[1];
        short curParentLen = retValues[2];
        short curParentVal = retValues[3];
        // Go inside the current tag
        // find the tag value in this tag
        short tagEnd = getTag(tag, mem, curParentVal, curParentLen, false, retValues);
        // Compare the returned value with the given value
        if (tagEnd != (short)-1 && valLen == retValues[2] &&
            Util.arrayCompare(val, valStart, mem, retValues[3],valLen) == 0) {
          retValues[0] = curParentStart;
          retValues[1] = curParentTag;
          retValues[2] = curParentLen;
          retValues[3] = curParentVal;
          return index;
        }
      }
    }
    return (short)-1;
  }
  public static short convertCoseSign1SignatureToAsn1(
      byte[] input, short offset, short len,
      byte[] scratchPad, short scratchPadOff, short scratchLen) {
    // SEQ [ INTEGER(r), INTEGER(s)]
    // write from bottom to the top
    if(len != 64 && len != 128 && len != 256){
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    short stackLen = (short) (len + 12);
    if(stackLen > scratchLen) return -1;
    short stackPtr = (short) (scratchPadOff + stackLen + 1);
    short end = stackPtr;
    short dataLen = (short)(len /2);

    // write s.
    stackPtr = pushInteger(scratchPad,stackPtr,stackLen,input,(short) (offset + dataLen), dataLen);
    // write r
    stackPtr = pushInteger(scratchPad,stackPtr,stackLen,input,offset, dataLen);
    short length = (short) (end - stackPtr);
    stackPtr = pushSequenceHeader(scratchPad,stackPtr,stackLen,length);
    length = (short) (end - stackPtr);
    if (stackPtr != scratchPadOff) {
      // re adjust the buffer
      Util.arrayCopyNonAtomic(scratchPad, stackPtr, scratchPad, scratchPadOff, length);
    }
    return length;
  }
}
