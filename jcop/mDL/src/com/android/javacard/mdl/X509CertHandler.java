package com.android.javacard.mdl;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;

// TODO this is a placeholder class until design is finalized. If KeyMint applet needs to be
//  integrated then this class will be replaced by some shareable interface implemented by the
//  KeyMint applet.
public class X509CertHandler {

  private static final short KEYMINT_VERSION = 300;
  private static final byte STRONGBOX = 2;
  private static final short ATTESTATION_VERSION = 300;
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
      /*
      0x2A, 0x31, 0x28, 0x30, 0x26, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x1F,
      0x41, 0x6E, 0x64, 0x72, 0x6F, 0x69, 0x64, 0x20, 0x49, 0x64, 0x65, 0x6E,
      0x74, 0x69, 0x74, 0x79, 0x20, 0x43, 0x72, 0x65, 0x64, 0x65, 0x6E, 0x74,
      0x69, 0x61, 0x6C, 0x20, 0x4B, 0x65, 0x79, 0x30, 0x59, 0x30, 0x13, 0x06,
      0x07, 0x2A, (byte)0x86, 0x48, (byte)0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, (byte)0x86,
      0x48, (byte)0xCE, 0x3D, 0x03, 0x01, 0x07,

       */
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
}
