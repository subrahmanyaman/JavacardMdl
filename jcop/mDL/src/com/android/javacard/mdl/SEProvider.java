package com.android.javacard.mdl;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.CryptoException;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.HMACKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.MessageDigest;
import javacard.security.RandomData;
import javacard.security.Signature;
import javacardx.crypto.*;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

// This class implements JCardSim implementation. The JCOP implementation is found in
// com.android.javacard.mdl.andoidse package.

public class SEProvider {

  public static final byte AES_GCM_NONCE_LENGTH = (byte)12;
  public static final byte AES_GCM_TAG_LENGTH = 16;
  public static final short SIGNING_CERT_MAX_SIZE = 512;

  //private final KMSEProvider kmSEProvider;
  private final Signature mHMACSignature;
  private final KeyPair mECKeyPair1;
  private final KeyAgreement mECDHAgreement;
  private Signature signerNoDigest;
  private Signature signerWithSha256;
  private KeyPair ecKeyPair;
  private byte[] mScratchPad;
  private static SEProvider inst;
  private javax.crypto.Cipher mCipher;


  public static SEProvider instance(){
    if(inst == null){
      inst = new SEProvider();
      X509CertHandler.init((short)4096);
    }
    return inst;
  }
  private SEProvider(){
    //kmSEProvider = new KMJCardSimulator();
    mScratchPad = JCSystem.makeTransientByteArray((short)512, JCSystem.CLEAR_ON_DESELECT);
    mHMACSignature = Signature.getInstance(Signature.ALG_HMAC_SHA_256, false);
    mECKeyPair1 = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
    mECDHAgreement = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN, false);
    ecKeyPair = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
    signerNoDigest = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
    signerWithSha256 = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);

  }


  public static short ecSign256(
      ECPrivateKey key,
      byte[] inputDataBuf,
      short inputDataStart,
      short inputDataLength,
      byte[] outputDataBuf,
      short outputDataStart) {
    byte[] tmp = new byte[32];
    short keyLen = key.getS(tmp,(short)0);
    Signature signer = Signature.getInstance(Signature.ALG_ECDSA_SHA_256,false);
/*      Signature  signer = Signature.getInstance(MessageDigest.ALG_SHA_256,
          Signature.SIG_CIPHER_ECDSA, javacardx.crypto.Cipher.PAD_NULL, false);
 */
      signer.init(key, Signature.MODE_SIGN);
      return signer.sign(
          inputDataBuf, inputDataStart, inputDataLength, outputDataBuf, outputDataStart);
  }

  private static java.security.Key convert(AESKey key){
    byte[] keyBuf = new byte[32];
    byte len = key.getKey(keyBuf, (short)0);
    return new SecretKeySpec(keyBuf, (short)0, len, "AES");
  }

  public void initCipher(
      java.security.Key aesKey,
      byte[] nonce,
      short nonceStart,
      short nonceLen,
      byte[] authData,
      short authDataStart,
      short authDataLen,
      short mode){
    // Create the cipher
    mCipher = null;
    try {
      mCipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding", "SunJCE");
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
    } catch (NoSuchProviderException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.INVALID_INIT);
    } catch (NoSuchPaddingException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }
    // Copy nonce
    if (nonceLen != AES_GCM_NONCE_LENGTH) {
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }
    byte[] iv = new byte[AES_GCM_NONCE_LENGTH];
    javacard.framework.Util.arrayCopyNonAtomic(nonce, nonceStart, iv, (short) 0, AES_GCM_NONCE_LENGTH);
    // Init SEProvider
    GCMParameterSpec spec = new GCMParameterSpec(AES_GCM_TAG_LENGTH * 8, nonce, nonceStart,
        AES_GCM_NONCE_LENGTH);
    try {
      mCipher.init(mode, aesKey, spec);
    } catch (InvalidKeyException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.INVALID_INIT);
    } catch (InvalidAlgorithmParameterException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
    }
    if (authDataLen != 0) {
      // Create auth data
      byte[] aad = new byte[authDataLen];
      javacard.framework.Util.arrayCopyNonAtomic(authData, authDataStart, aad, (short) 0, authDataLen);
      mCipher.updateAAD(aad);
    }
  }

  private  MessageDigest getMessageDigest256Instance(){
    return MessageDigest.getInstance(MessageDigest.ALG_SHA3_256, false);
  }

  public short digest(byte[] buffer, short start, short len, byte[] outBuf, short index){
    return getMessageDigest256Instance().doFinal(buffer,start,len,outBuf,index);
  }

  public void beginAesGcmOperation(AESKey key, boolean encrypt,
      byte[] nonce, short start, short len,
      byte[] authData,
      short authDataStart,
      short authDataLen){
    //Create the sun jce compliant aes key
    java.security.Key aesKey = convert(key);
    // Create the cipher
    short mode = encrypt ? (short) Cipher.ENCRYPT_MODE : (short) Cipher.DECRYPT_MODE;
    initCipher(aesKey,nonce,start,len, authData, authDataStart, authDataLen, mode);

  }
  public short doAesGcmOperation(
      byte[] inData, short inDataStart, short inDataLen,
      byte[] outData, short outDataStart, boolean justUpdate) {
    // Encrypt
    short len = 0;
    byte[] outputBuf = new byte[mCipher.getOutputSize(inDataLen)];
    try {
      if(!justUpdate) {
        len = (short) (mCipher.doFinal(inData, inDataStart, inDataLen, outputBuf, (short) 0));
      }else{
        len = (short) (mCipher.update(inData, inDataStart, inDataLen, outputBuf, (short) 0));
      }
    } catch (AEADBadTagException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    } catch (ShortBufferException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    } catch (IllegalBlockSizeException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    } catch (BadPaddingException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }
    //Copy the encrypted data
    javacard.framework.Util.arrayCopyNonAtomic(outputBuf, (short) 0, outData, outDataStart, len);
    return len;
  }

  public static void assertApdu(APDU apdu){
    /*
    byte protocol = (byte) (APDU.getProtocol() & APDU.PROTOCOL_MEDIA_MASK);
    if (protocol != APDU.PROTOCOL_MEDIA_CONTACTLESS_TYPE_A &&
        protocol != APDU.PROTOCOL_MEDIA_CONTACTLESS_TYPE_B) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
 */
  }


  
  public void createECKey(byte[] privKeyBuf, short privKeyStart, short privKeyMaxLength,
      byte[] pubModBuf, short pubModStart, short pubModMaxLength, short[] lengths) {
    ecKeyPair.genKeyPair();
    ECPrivateKey privateKey = (ECPrivateKey) ecKeyPair.getPrivate();
    lengths[0] = privateKey.getS(privKeyBuf, privKeyStart);
    ECPublicKey publicKey = (ECPublicKey) ecKeyPair.getPublic();
    lengths[1] = publicKey.getW(pubModBuf, pubModStart);
  }

  
  public short ecSignWithNoDigest(byte[] privKeyBuf, short privKeyStart, short privKeyLength,
      byte[] data, short dataStart, short dataLength,
      byte[] outSign, short outSignStart) {

    ECPrivateKey key = (ECPrivateKey) ecKeyPair.getPrivate();
    key.setS(privKeyBuf, privKeyStart, privKeyLength);
    signerNoDigest.init(key, Signature.MODE_SIGN);
    return signerNoDigest.signPreComputedHash(data, dataStart, dataLength, outSign, outSignStart);
  }

  // TODO change the follwing and merge with one shot aes gcm methods.
  
  public short aesGCMEncrypt(byte[] aesKeyBuf, short aesKeyStart, short aesKeyLen, byte[] data,
      short dataStart,
      short dataLen, byte[] encData, short encDataStart, byte[] nonce, short nonceStart, short nonceLen,
      byte[] authData, short authDataStart, short authDataLen, byte[] authTag, short authTagStart,
      short authTagLen) {
    // Create the sun jce compliant aes key
    if (aesKeyLen != 32 && aesKeyLen != 16) {
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }
    java.security.Key aesKey = new SecretKeySpec(aesKeyBuf, aesKeyStart, aesKeyLen, "AES");
    // Create the cipher
    javax.crypto.Cipher cipher = null;
    try {
      cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding", "SunJCE");
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
    } catch (NoSuchProviderException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.INVALID_INIT);
    } catch (NoSuchPaddingException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }
    // Copy nonce
    if (nonceLen != AES_GCM_NONCE_LENGTH) {
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }
    byte[] iv = new byte[AES_GCM_NONCE_LENGTH];
    javacard.framework.Util.arrayCopyNonAtomic(nonce, nonceStart, iv, (short) 0, AES_GCM_NONCE_LENGTH);
    // Init Cipher
    GCMParameterSpec spec =
        new GCMParameterSpec(AES_GCM_TAG_LENGTH * 8, nonce, nonceStart, AES_GCM_NONCE_LENGTH);
    try {
      cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, aesKey, spec);
    } catch (InvalidKeyException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.INVALID_INIT);
    } catch (InvalidAlgorithmParameterException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
    }
    if (authDataLen != 0) {
      // Create auth data
      byte[] aad = new byte[authDataLen];
      javacard.framework.Util.arrayCopyNonAtomic(authData, authDataStart, aad, (short) 0, authDataLen);
      cipher.updateAAD(aad);
    }
    // Encrypt secret
    short len = 0;
    byte[] outputBuf = new byte[cipher.getOutputSize(dataLen)];
    try {
      len = (short) (cipher.doFinal(data, dataStart, dataLen, outputBuf, (short) 0));
    } catch (ShortBufferException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    } catch (IllegalBlockSizeException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    } catch (BadPaddingException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }
    // Extract Tag appended at the end.
    javacard.framework.Util.arrayCopyNonAtomic(
        outputBuf, (short) (len - AES_GCM_TAG_LENGTH), authTag, authTagStart, AES_GCM_TAG_LENGTH);
    // Copy the encrypted data
    javacard.framework.Util.arrayCopyNonAtomic(
        outputBuf, (short) 0, encData, encDataStart, (short) (len - AES_GCM_TAG_LENGTH));
    return (short) (len - AES_GCM_TAG_LENGTH);
  }

  
  public boolean aesGCMDecrypt(byte[] aesKeyBuf, short aesKeyStart, short aesKeyLen, byte[] data,
      short dataStart,
      short dataLen, byte[] encData, short encDataStart, byte[] nonce, short nonceStart, short nonceLen,
      byte[] authData, short authDataStart, short authDataLen, byte[] authTag, short authTagStart,
      short authTagLen) {
    // Create the sun jce compliant aes key
    if (aesKeyLen != 32 && aesKeyLen != 16) {
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }
    java.security.Key aesKey = new SecretKeySpec(aesKeyBuf, aesKeyStart, aesKeyLen, "AES");
    // Create the cipher
    javax.crypto.Cipher cipher = null;
    try {
      cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding", "SunJCE");
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
    } catch (NoSuchProviderException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.INVALID_INIT);
    } catch (NoSuchPaddingException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }
    // Copy nonce
    if (nonceLen != AES_GCM_NONCE_LENGTH) {
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }
    byte[] iv = new byte[AES_GCM_NONCE_LENGTH];
    javacard.framework.Util.arrayCopyNonAtomic(nonce, nonceStart, iv, (short) 0, AES_GCM_NONCE_LENGTH);
    // Init Cipher
    GCMParameterSpec spec =
        new GCMParameterSpec(authTagLen * 8, nonce, nonceStart, AES_GCM_NONCE_LENGTH);
    try {
      cipher.init(javax.crypto.Cipher.DECRYPT_MODE, aesKey, spec);
    } catch (InvalidKeyException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.INVALID_INIT);
    } catch (InvalidAlgorithmParameterException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
    }
    if (authDataLen != 0) {
      // Create auth data
      byte[] aad = new byte[authDataLen];
      javacard.framework.Util.arrayCopyNonAtomic(authData, authDataStart, aad, (short) 0, authDataLen);
      cipher.updateAAD(aad);
    }
    // Append the auth tag at the end of data
    byte[] inputBuf = new byte[(short) (dataLen + authTagLen)];
    javacard.framework.Util.arrayCopyNonAtomic(data, dataStart, inputBuf, (short) 0,
        dataLen);
    javacard.framework.Util.arrayCopyNonAtomic(authTag, authTagStart, inputBuf, dataLen, authTagLen);
    // Decrypt
    short len = 0;
    byte[] outputBuf = new byte[cipher.getOutputSize((short) inputBuf.length)];
    try {
      len =
          (short)
              (cipher.doFinal(inputBuf, (short) 0, (short) inputBuf.length, outputBuf, (short) 0));
    } catch (AEADBadTagException e) {
      e.printStackTrace();
      return false;
    } catch (ShortBufferException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    } catch (IllegalBlockSizeException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    } catch (BadPaddingException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }
    // Copy the decrypted data
    javacard.framework.Util.arrayCopyNonAtomic(outputBuf, (short) 0, encData, encDataStart, len);
    return true;
  }

  
  public short ecSignWithSHA256Digest(byte[] privKeyBuf, short privKeyStart, short privKeyLength,
      byte[] data, short dataStart, short dataLength,
      byte[] outSign, short outSignStart) {
    ECPrivateKey key = (ECPrivateKey)ecKeyPair.getPrivate();
    key.setS(privKeyBuf, privKeyStart, privKeyLength);
    return ecSignWithSHA256Digest(key, data, dataStart, dataLength, outSign, outSignStart);
  }
  public short ecSignWithSHA256Digest(ECPrivateKey key, byte[] data, short dataStart, short dataLength,
      byte[] outSign, short outSignStart) {
    signerWithSha256.init(key, Signature.MODE_SIGN);
    return signerWithSha256.sign(data, dataStart, dataLength, outSign, outSignStart);
  }
  
  public boolean ecVerifyWithNoDigest(byte[] pubKeyBuf, short pubKeyStart, short pubKeyLength,
      byte[] data, short dataStart, short dataLength,
      byte[] signBuf, short signStart, short signLength) {
    ECPublicKey pubKey = (ECPublicKey)ecKeyPair.getPublic();
    pubKey.setW(pubKeyBuf, pubKeyStart, pubKeyLength);
    signerNoDigest.init(pubKey, Signature.MODE_VERIFY);
    return signerNoDigest.verifyPreComputedHash(data, dataStart, dataLength, signBuf, signStart, signLength);
  }

  
  public short createECDHSecret(byte[] privKey, short privKeyOffset, short privKeyLen,
      byte[] pubKey, short pubKeyOffset, short pubKeyLen,
      byte[] outSecret, short outSecretOffset) {
    ECPrivateKey privateKey = (ECPrivateKey) mECKeyPair1.getPrivate();
    privateKey.setS(privKey, privKeyOffset, privKeyLen);
    mECDHAgreement.init(privateKey);
    short result = (short)0;
    try {
      result = mECDHAgreement.generateSecret(pubKey, pubKeyOffset, pubKeyLen, outSecret, outSecretOffset);
    }catch (Exception e){
      e.printStackTrace();
    }
    return result;
  }

  
  public short hkdf(byte[] sharedSecret, short sharedSecretOffset, short sharedSecretLen,
      byte[] salt, short saltOffset, short saltLen,
      byte[] info, short infoOffset, short infoLen,
      byte[] outDerivedKey, short outDerivedKeyOffset, short expectedDerivedKeyLen) {
    // HMAC_extract
    byte[] prk = new byte[32];
    hkdfExtract(sharedSecret, sharedSecretOffset, sharedSecretLen, salt, saltOffset, saltLen, prk, (short) 0);
    //HMAC_expand
    return hkdfExpand(prk, (short) 0, (short) 32, info, infoOffset, infoLen, outDerivedKey, outDerivedKeyOffset, expectedDerivedKeyLen);
  }

  private short hkdfExtract(byte[] ikm, short ikmOff, short ikmLen, byte[] salt, short saltOff, short saltLen,
      byte[] out, short off) {
    // https://tools.ietf.org/html/rfc5869#section-2.2
    HMACKey hmacKey = createHMACKey(salt, saltOff, saltLen);
    mHMACSignature.init(hmacKey, Signature.MODE_SIGN);
    return mHMACSignature.sign(ikm, ikmOff, ikmLen, out, off);
  }

  private short hkdfExpand(byte[] prk, short prkOff, short prkLen, byte[] info, short infoOff, short infoLen,
      byte[] out, short outOff, short outLen) {
    // https://tools.ietf.org/html/rfc5869#section-2.3
    short digestLen = (short) 32; // SHA256 digest length.
    // Calculate no of iterations N.
    short n = (short) ((outLen + digestLen - 1) / digestLen);
    if (n > 255) {
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }
    HMACKey hmacKey = createHMACKey(prk, prkOff, prkLen);
    byte[] previousOutput = new byte[32]; // Length of output 32.
    byte[] cnt = {(byte) 0};
    short bytesCopied = 0;
    short len = 0;
    for (short i = 0; i < n; i++) {
      cnt[0]++;
      mHMACSignature.init(hmacKey, Signature.MODE_SIGN);
      if (i != 0)
        mHMACSignature.update(previousOutput, (short) 0, (short) 32);
      mHMACSignature.update(info, infoOff, infoLen);
      len = mHMACSignature.sign(cnt, (short) 0, (short) 1, previousOutput, (short) 0);
      if ((short) (bytesCopied + len) > outLen) {
        len = (short) (outLen - bytesCopied);
      }
      javacard.framework.Util.arrayCopyNonAtomic(previousOutput, (short) 0, out, (short) (outOff + bytesCopied), len);
      bytesCopied += len;
    }
    return outLen;
  }
  public HMACKey createHMACKey(byte[] secretBuffer, short secretOff, short secretLength) {
    HMACKey key = null;
    key = (HMACKey) KeyBuilder.buildKey(KeyBuilder.TYPE_HMAC,
        KeyBuilder.LENGTH_HMAC_SHA_256_BLOCK_64, false);
    key.setKey(secretBuffer, secretOff, secretLength);
    return key;
  }

  
  public boolean hmacVerify(byte[] key, short keyOffset, short keyLen, byte[] data, short dataOffset, short dataLen, byte[] mac, short macOffset, short macLen) {
    HMACKey hmacKey = createHMACKey(key, keyOffset, keyLen);
    mHMACSignature.init(hmacKey, Signature.MODE_VERIFY);
    return mHMACSignature.verify(data, dataOffset, dataLen, mac, macOffset, macLen);
  }

  
  public short hmacSign(byte[] key, short keyOffset, short keyLen, byte[] data, short dataOffset,
      short dataLen, byte[] mac, short macOffset) {
    HMACKey hmacKey = createHMACKey(key, keyOffset, keyLen);
    mHMACSignature.init(hmacKey, Signature.MODE_SIGN);
    return mHMACSignature.sign(data, dataOffset, dataLen, mac, macOffset);
  }

  
  public boolean validateAuthToken(byte[] tokenData, short tokenOffset, short tokenLen) {
    return false;//TODO Should we support validation HW token from JCard based Keymaster applet?
  }

  
  public boolean verifyCertByPubKey(byte[] cert, short certOffset, short certLen,
      byte[] pubKey, short pubKeyOffset, short pubKeyLen) {
    if(certLen <= 0 || cert[0] != 0x30) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
    short tbsStart = 0;
    for(short i = (short) (certOffset + 1); i < (short)(certOffset + 5); i++) {
      if(cert[i] == 0x30) {
        tbsStart = i;
        break;
      }
    }
    if(tbsStart == 0) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
    short tbsLen;
    if(cert[tbsStart + 1] == (byte)0x81) {
      tbsLen = (short)(cert[tbsStart + 2] & 0x00FF);
      tbsLen += 3;
    } else if(cert[tbsStart + 1] == (byte)0x82) {
      tbsLen = javacard.framework.Util.getShort(cert, (short) (tbsStart + 2));
      tbsLen += 4;
    } else {
      tbsLen = (short)(cert[tbsStart + 1] & 0x00FF);
      tbsLen += 2;
    }

    short signSeqStart = (short)(tbsStart + tbsLen + (byte)12/*OID TAG*/);
    if(cert[signSeqStart] != 0x03 && cert[(short)(signSeqStart + (byte)2)] != 0x00) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
    byte signLen = (byte)(cert[signSeqStart + (byte)1] - (byte)1);//Actual signature Bit string starts after 0x00. signature len expected around 70-72

    ECPublicKey publicKey = (ECPublicKey)ecKeyPair.getPublic();
    publicKey.setW(pubKey, pubKeyOffset, pubKeyLen);
    signerWithSha256.init(publicKey, Signature.MODE_VERIFY);
    return signerWithSha256.verify(cert, tbsStart, tbsLen, cert, (short) (certOffset + certLen - signLen), signLen);
  }

  public void generateRandomData(byte[] tempBuffer, short offset, short length) {
    RandomData rng = RandomData.getInstance(RandomData.ALG_TRNG);
    rng.nextBytes(tempBuffer, offset, length);
  }

  public static void print(byte[] buf, short start, short length) {
//    StringBuilder sb = new StringBuilder();
//    System.out.println("----");
//    for (int i = start; i < (start + length); i++) {
//      sb.append(String.format("%02X", buf[i]));
//    }
//    System.out.println(sb);
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
    return X509CertHandler.generateCredKeyCert(credPubKey,
    osVersion,osVersionStart,osVersionLen,
    osPatchLevel,osPatchLevelStart,osPatchLevelLen,
    challenge,challengeStart,challengeLen,
    notBefore,notBeforeStart,notBeforeLen,
    notAfter,notAfterStart,notAfterLen,
    creationDateTime,creationDateTimeStart,creationDateTimeLen,
    attAppId,attAppIdStart,attAppIdLen, testCredential,
    buf,start,len,
    scratch,scratchStart,scratchLen);
  }

  public static short generateSigningKeyCert(ECPublicKey signingPubKey, ECPrivateKey attestKey,
      byte[] notBefore, short notBeforeStart, short notBeforeLen,
      byte[] notAfter, short notAfterStart, short notAfterLen,
      byte[] buf, short start, short len,
      byte[] scratch, short scratchStart, short scratchLen){
    return X509CertHandler.generateSigningKeyCert(signingPubKey, attestKey,
        notBefore,notBeforeStart,notBeforeLen,
        notAfter,notAfterStart,notAfterLen,
        buf,start,len,
        scratch,scratchStart,scratchLen);
  }
  public static short aesGCMEncryptOneShot(
      AESKey key,
      byte[] secret,
      short secretStart,
      short secretLen,
      byte[] encSecret,
      short encSecretStart,
      byte[] nonce,
      short nonceStart,
      short nonceLen,
      byte[] authData,
      short authDataStart,
      short authDataLen,
      boolean justUpdate) {
    //Create the sun jce compliant aes key
    java.security.Key aesKey = convert(key);
    // Create the cipher
    Cipher cipher = getCipherInstance(aesKey,nonce,nonceStart,nonceLen,authData,authDataStart,
        authDataLen, (short) Cipher.ENCRYPT_MODE);
    // Encrypt
    short len = 0;
    byte[] outputBuf = new byte[cipher.getOutputSize(secretLen)];
    try {
      if(!justUpdate) {
        len = (short) (cipher.doFinal(secret, secretStart, secretLen, outputBuf, (short) 0));
      }else{
        len = (short) (cipher.update(secret, secretStart, secretLen, outputBuf, (short) 0));
      }
    } catch (ShortBufferException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    } catch (IllegalBlockSizeException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    } catch (BadPaddingException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }

    //Copy the encrypted data
    javacard.framework.Util.arrayCopyNonAtomic(outputBuf, (short) 0, encSecret, encSecretStart, len);
    return len;
  }
  public short encryptDecryptInPlace(byte[] buf, short start, short len,
      byte[] scratch, short scratchStart, short scratchLen){
    short inOffset = start;
    short outOffset = start;
    while(scratchLen < len){
      Util.arrayCopyNonAtomic(buf, inOffset, scratch,scratchStart, scratchLen);
      outOffset +=doAesGcmOperation(
          scratch,scratchStart, scratchLen, buf, outOffset, true);
      inOffset += scratchLen;
      len -= scratchLen;
    }
    if (len > 0){
      Util.arrayCopyNonAtomic(buf, inOffset, scratch,scratchStart, len);
      outOffset += doAesGcmOperation(
          scratch,scratchStart, len, buf, outOffset, true);
    }
    return outOffset;
  }

  public static short aesGCMDecryptOneShot(
      AESKey key,
      byte[] encSecret,
      short encSecretStart,
      short encSecretLen,
      byte[] secret,
      short secretStart,
      byte[] nonce,
      short nonceStart,
      short nonceLen,
      byte[] authData,
      short authDataStart,
      short authDataLen,
      boolean justUpdate){
    java.security.Key aesKey = convert(key);
    // Create the cipher
    Cipher cipher = getCipherInstance(aesKey,nonce,nonceStart,nonceLen,authData,authDataStart,
        authDataLen, (short) Cipher.DECRYPT_MODE);
    // Decrypt
    short len = 0;
    byte[] outputBuf = new byte[cipher.getOutputSize(encSecretLen)];
    try {
      if(!justUpdate) {
        len = (short) (cipher.doFinal(encSecret, encSecretStart,
            encSecretLen, outputBuf, (short) 0));
      }else{
        len = (short) (cipher.update(encSecret, encSecretStart,
            encSecretLen, outputBuf, (short) 0));
      }
    } catch (AEADBadTagException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    } catch (ShortBufferException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    } catch (IllegalBlockSizeException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    } catch (BadPaddingException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }
    // Copy the decrypted data
    javacard.framework.Util.arrayCopyNonAtomic(outputBuf, (short) 0, secret, secretStart, len);
    return len;
  }
  private static Cipher getCipherInstance(
      java.security.Key aesKey,
      byte[] nonce,
      short nonceStart,
      short nonceLen,
      byte[] authData,
      short authDataStart,
      short authDataLen,
      short mode){
    // Create the cipher
    Cipher cipher = null;
    try {
      cipher = Cipher.getInstance("AES/GCM/NoPadding", "SunJCE");
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
    } catch (NoSuchProviderException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.INVALID_INIT);
    } catch (NoSuchPaddingException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }
    // Copy nonce
    if (nonceLen != AES_GCM_NONCE_LENGTH) {
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }
    byte[] iv = new byte[AES_GCM_NONCE_LENGTH];
    javacard.framework.Util.arrayCopyNonAtomic(nonce, nonceStart, iv, (short) 0, AES_GCM_NONCE_LENGTH);
    // Init SEProvider
    GCMParameterSpec spec = new GCMParameterSpec(AES_GCM_TAG_LENGTH * 8, nonce, nonceStart,
        AES_GCM_NONCE_LENGTH);
    try {
      cipher.init(mode, aesKey, spec);
    } catch (InvalidKeyException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.INVALID_INIT);
    } catch (InvalidAlgorithmParameterException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
    }
    if (authDataLen != 0) {
      // Create auth data
      byte[] aad = new byte[authDataLen];
      javacard.framework.Util.arrayCopyNonAtomic(authData, authDataStart, aad, (short) 0, authDataLen);
      cipher.updateAAD(aad);
    }
    return cipher;
  }
}
