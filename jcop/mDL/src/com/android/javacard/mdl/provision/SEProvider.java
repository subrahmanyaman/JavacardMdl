package com.android.javacard.mdl.provision;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.CryptoException;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.MessageDigest;
import javacard.security.RandomData;
import javacard.security.Signature;
import javacardx.crypto.AEADCipher;
import javacardx.crypto.Cipher;

// This class implements JCardSim implementation. The JCOP implementation is found in
// com.android.javacard.mdl.andoidse package.

public class SEProvider {

  public static final byte AES_GCM_NONCE_LENGTH = (byte)12;
  public static final byte AES_GCM_TAG_LENGTH = 16;
  public static final short SIGNING_CERT_MAX_SIZE = 512;
  public static final short ES256 = 1;
  public static final short ES384 = 2;
  public static final short ES512 = 3;
  // parameters offset
  public static final short PARAM_OFF_AES_GCM_OUT_LEN = 0; 
  public static final short PARAM_OFF_PURPOSE = 1;  
  public static final short PARAMS_COUNT = 2;
  private Signature signerWithSha256;
  private KeyPair ecKeyPair;
  public static short PROVIDER_INST_PRESENTATION = 1;
  public static short PROVIDER_INST_PROVISION = 0;
  private static SEProvider inst;
 private AEADCipher aesGcmCipher;
  private RandomData mRng;
  // static final variables
  // --------------------------------------------------------------
  // P-256 Curve Parameters
  static byte[] secp256r1_P;
  static byte[] secp256r1_A;

  static byte[] secp256r1_B;
  static byte[] secp256r1_S;

  // Uncompressed form
  static byte[] secp256r1_UCG;
  static byte[] secp256r1_N;
  static final byte secp256r1_H = 1;
  // --------------------------------------------------------------
  private short[] parameters;
  public static SEProvider instance() {
    if(inst == null){
      inst = new SEProvider();
      X509CertHandler.init((short)4096);
    }
    return inst;
  }
  private SEProvider() {
    initStatics();
    parameters = JCSystem.makeTransientShortArray(PARAMS_COUNT, JCSystem.CLEAR_ON_RESET);
    ecKeyPair = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
    initECKey(ecKeyPair);
    signerWithSha256 = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
    aesGcmCipher = (AEADCipher) Cipher.getInstance(AEADCipher.ALG_AES_GCM, false);
    mRng = RandomData.getInstance(RandomData.ALG_TRNG);
  }
  
  public static void initStatics() {
    secp256r1_P =
        new byte[] {
          (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x00, (byte) 0x00,
          (byte) 0x00, (byte) 0x01, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
          (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
          (byte) 0x00, (byte) 0x00, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
          (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
          (byte) 0xFF, (byte) 0xFF
        };

    secp256r1_A =
        new byte[] {
          (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x00, (byte) 0x00,
          (byte) 0x00, (byte) 0x01, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
          (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
          (byte) 0x00, (byte) 0x00, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
          (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
          (byte) 0xFF, (byte) 0xFC
        };

    secp256r1_B =
        new byte[] {
          (byte) 0x5A, (byte) 0xC6, (byte) 0x35, (byte) 0xD8, (byte) 0xAA, (byte) 0x3A,
          (byte) 0x93, (byte) 0xE7, (byte) 0xB3, (byte) 0xEB, (byte) 0xBD, (byte) 0x55,
          (byte) 0x76, (byte) 0x98, (byte) 0x86, (byte) 0xBC, (byte) 0x65, (byte) 0x1D,
          (byte) 0x06, (byte) 0xB0, (byte) 0xCC, (byte) 0x53, (byte) 0xB0, (byte) 0xF6,
          (byte) 0x3B, (byte) 0xCE, (byte) 0x3C, (byte) 0x3E, (byte) 0x27, (byte) 0xD2,
          (byte) 0x60, (byte) 0x4B
        };

    secp256r1_S =
        new byte[] {
          (byte) 0xC4, (byte) 0x9D, (byte) 0x36, (byte) 0x08, (byte) 0x86, (byte) 0xE7,
          (byte) 0x04, (byte) 0x93, (byte) 0x6A, (byte) 0x66, (byte) 0x78, (byte) 0xE1,
          (byte) 0x13, (byte) 0x9D, (byte) 0x26, (byte) 0xB7, (byte) 0x81, (byte) 0x9F,
          (byte) 0x7E, (byte) 0x90
        };

    // Uncompressed form
    secp256r1_UCG =
        new byte[] {
          (byte) 0x04, (byte) 0x6B, (byte) 0x17, (byte) 0xD1, (byte) 0xF2, (byte) 0xE1,
          (byte) 0x2C, (byte) 0x42, (byte) 0x47, (byte) 0xF8, (byte) 0xBC, (byte) 0xE6,
          (byte) 0xE5, (byte) 0x63, (byte) 0xA4, (byte) 0x40, (byte) 0xF2, (byte) 0x77,
          (byte) 0x03, (byte) 0x7D, (byte) 0x81, (byte) 0x2D, (byte) 0xEB, (byte) 0x33,
          (byte) 0xA0, (byte) 0xF4, (byte) 0xA1, (byte) 0x39, (byte) 0x45, (byte) 0xD8,
          (byte) 0x98, (byte) 0xC2, (byte) 0x96, (byte) 0x4F, (byte) 0xE3, (byte) 0x42,
          (byte) 0xE2, (byte) 0xFE, (byte) 0x1A, (byte) 0x7F, (byte) 0x9B, (byte) 0x8E,
          (byte) 0xE7, (byte) 0xEB, (byte) 0x4A, (byte) 0x7C, (byte) 0x0F, (byte) 0x9E,
          (byte) 0x16, (byte) 0x2B, (byte) 0xCE, (byte) 0x33, (byte) 0x57, (byte) 0x6B,
          (byte) 0x31, (byte) 0x5E, (byte) 0xCE, (byte) 0xCB, (byte) 0xB6, (byte) 0x40,
          (byte) 0x68, (byte) 0x37, (byte) 0xBF, (byte) 0x51, (byte) 0xF5
        };

    secp256r1_N =
        new byte[] {
          (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x00, (byte) 0x00,
          (byte) 0x00, (byte) 0x00, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
          (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xBC, (byte) 0xE6,
          (byte) 0xFA, (byte) 0xAD, (byte) 0xA7, (byte) 0x17, (byte) 0x9E, (byte) 0x84,
          (byte) 0xF3, (byte) 0xB9, (byte) 0xCA, (byte) 0xC2, (byte) 0xFC, (byte) 0x63,
          (byte) 0x25, (byte) 0x51
        };
  }
  
  public static void initECKey(KeyPair ecKeyPair) {
    ECPrivateKey privKey = (ECPrivateKey) ecKeyPair.getPrivate();
    ECPublicKey pubkey = (ECPublicKey) ecKeyPair.getPublic();
    pubkey.setFieldFP(secp256r1_P, (short) 0, (short) secp256r1_P.length);
    pubkey.setA(secp256r1_A, (short) 0, (short) secp256r1_A.length);
    pubkey.setB(secp256r1_B, (short) 0, (short) secp256r1_B.length);
    pubkey.setG(secp256r1_UCG, (short) 0, (short) secp256r1_UCG.length);
    pubkey.setK(secp256r1_H);
    pubkey.setR(secp256r1_N, (short) 0, (short) secp256r1_N.length);

    privKey.setFieldFP(secp256r1_P, (short) 0, (short) secp256r1_P.length);
    privKey.setA(secp256r1_A, (short) 0, (short) secp256r1_A.length);
    privKey.setB(secp256r1_B, (short) 0, (short) secp256r1_B.length);
    privKey.setG(secp256r1_UCG, (short) 0, (short) secp256r1_UCG.length);
    privKey.setK(secp256r1_H);
    privKey.setR(secp256r1_N, (short) 0, (short) secp256r1_N.length);
  }


  public short ecSign256(
      ECPrivateKey key,
      byte[] inputDataBuf,
      short inputDataStart,
      short inputDataLength,
      byte[] outputDataBuf,
      short outputDataStart) {
    try {
    signerWithSha256.init(key, Signature.MODE_SIGN);
    return signerWithSha256.sign(
          inputDataBuf, inputDataStart, inputDataLength, outputDataBuf, outputDataStart);
    } catch(CryptoException e) {
      ISOException.throwIt(e.getReason());
    }
    return 0;
  }

  private  MessageDigest getMessageDigest256Instance(){
    return MessageDigest.getInstance(MessageDigest.ALG_SHA3_256, false);
  }

  public short digest(byte[] buffer, short start, short len, byte[] outBuf, short index){
    return getMessageDigest256Instance().doFinal(buffer,start,len,outBuf,index);
  }
  
  public short getAESGCMOutputSize(short dataSize) {
    if (parameters[PARAM_OFF_PURPOSE] == Cipher.MODE_ENCRYPT) {
      return (short) (parameters[PARAM_OFF_AES_GCM_OUT_LEN] + dataSize);
    } else {
      return (short) (parameters[PARAM_OFF_AES_GCM_OUT_LEN] + dataSize);
    }
  }

  public void beginAesGcmOperation(AESKey key, boolean encrypt,
      byte[] nonce, short start, short len,
      byte[] authData,
      short authDataStart,
      short authDataLen){
    parameters[PARAM_OFF_PURPOSE] = 0;
    parameters[PARAM_OFF_AES_GCM_OUT_LEN] = 0;
    // Create the cipher
    byte mode = encrypt ? Cipher.MODE_ENCRYPT : Cipher.MODE_DECRYPT;
    initCipher(key,nonce,start,len, authData, authDataStart, authDataLen, mode);
    parameters[PARAM_OFF_PURPOSE] = mode;
  }
  
  
  public short doAesGcmOperation(
      byte[] inData, short inDataStart, short inDataLen,
      byte[] outData, short outDataStart, boolean justUpdate) {
    // Encrypt
    short len = 0;
    short mode = parameters[PARAM_OFF_PURPOSE];
    //byte[] outputBuf = new byte[getAESGCMOutputSize(inDataLen)];
    //try {
      if(!justUpdate) {
        parameters[PARAM_OFF_PURPOSE] = 0;
        parameters[PARAM_OFF_AES_GCM_OUT_LEN] = 0;
        if (mode == Cipher.MODE_ENCRYPT) {
          len = (short) (aesGcmCipher.doFinal(inData, inDataStart, inDataLen, outData, outDataStart));
          aesGcmCipher.retrieveTag(outData, (short) (outDataStart + len), AES_GCM_TAG_LENGTH);
          len = 16;
        } else {
          // TODO Buffer the 16 bytes in the update to be used in verifyTag
          short tagOffset = (short) (inDataStart + inDataLen - AES_GCM_TAG_LENGTH);
          len = (short) (aesGcmCipher.doFinal(inData, inDataStart, 
              (short) (inDataLen - AES_GCM_TAG_LENGTH), outData, outDataStart));
          boolean verified = 
              aesGcmCipher.verifyTag(inData, tagOffset, AES_GCM_TAG_LENGTH, AES_GCM_TAG_LENGTH);
          if (!verified) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
          }
        }
      }else{
        len = (short) (aesGcmCipher.update(inData, inDataStart, inDataLen, outData, outDataStart));
        parameters[PARAM_OFF_AES_GCM_OUT_LEN] += (short) (inDataLen - len);
      }
    //Copy the encrypted data
    //Util.arrayCopyNonAtomic(scratchpad, scratchOff, outData, outDataStart, len);
    return len;
  }


  public void generateRandomData(byte[] tempBuffer, short offset, short length) {
    mRng.nextBytes(tempBuffer, offset, length);
    print(tempBuffer, offset, length);
  }

  public static void print(byte[] buf, short start, short length) {
//    StringBuilder sb = new StringBuilder();
//    System.out.println("----");
//    for (int i = start; i < (start + length); i++) {
//      sb.append(String.format("%02X", buf[i]));
//    }
//    System.out.println(sb);
  }
  public short generateCredKeyCert(ECPublicKey credPubKey,
      byte[] osVersion, short osVersionStart, short osVersionLen,
      byte[] osPatchLevel, short osPatchLevelStart, short osPatchLevelLen,
      byte[] challenge, short challengeStart, short challengeLen,
      byte[] notBefore, short notBeforeStart, short notBeforeLen,
      byte[] notAfter, short notAfterStart, short notAfterLen,
      byte[] creationDateTime, short creationDateTimeStart, short creationDateTimeLen,
      byte[] attAppId, short attAppIdStart, short attAppIdLen, boolean testCredential,
      byte[] buf, short start, short len,
      byte[] scratch, short scratchStart, short scratchLen){
    return X509CertHandler.generateCredKeyCert(this, credPubKey,
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

  public short generateSigningKeyCert(ECPublicKey signingPubKey, ECPrivateKey attestKey,
      byte[] notBefore, short notBeforeStart, short notBeforeLen,
      byte[] notAfter, short notAfterStart, short notAfterLen,
      byte[] buf, short start, short len,
      byte[] scratch, short scratchStart, short scratchLen){
    return X509CertHandler.generateSigningKeyCert(this, signingPubKey, attestKey,
        notBefore,notBeforeStart,notBeforeLen,
        notAfter,notAfterStart,notAfterLen,
        buf,start,len,
        scratch,scratchStart,scratchLen);
  }
  public short aesGCMEncryptOneShot(
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
    // Create the cipher
    initCipher(key,nonce,nonceStart,nonceLen,authData,authDataStart,
        authDataLen, Cipher.MODE_ENCRYPT);
    if (authDataLen != 0) {
      aesGcmCipher.updateAAD(authData, authDataStart, authDataLen);
    }
    return aesGcmCipher.doFinal(secret, secretStart, secretLen, encSecret, encSecretStart);
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

  public short aesGCMDecryptOneShot(
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
    // Create the cipher
    initCipher(key,nonce,nonceStart,nonceLen,authData,authDataStart,
        authDataLen, Cipher.MODE_DECRYPT);
    return aesGcmCipher.doFinal(encSecret, encSecretStart, encSecretLen, secret, secretStart);

  }
  public void initCipher(
      AESKey aesKey,
      byte[] nonce,
      short nonceStart,
      short nonceLen,
      byte[] authData,
      short authDataStart,
      short authDataLen,
      byte mode){
    //Create the sun jce compliant aes key
    //java.security.Key key = convert(aesKey);
    // Copy nonce
    if (nonceLen != AES_GCM_NONCE_LENGTH) {
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }
//    byte[] iv = new byte[AES_GCM_NONCE_LENGTH];
//    Util.arrayCopyNonAtomic(nonce, nonceStart, iv, (short) 0, AES_GCM_NONCE_LENGTH);
    
    if (aesGcmCipher == null) {
      aesGcmCipher = (AEADCipher) Cipher.getInstance(AEADCipher.ALG_AES_GCM, false);
    }
    aesGcmCipher.init(aesKey, mode, nonce, nonceStart, nonceLen);

    if (authDataLen != 0) {
      aesGcmCipher.updateAAD(authData, authDataStart, authDataLen);
    }
  }

  public boolean validateEcDsaSign(byte[] buf,
      short toBeSignedStart, short toBeSignedLen,
      short alg,
      byte[] sign, short signStart, short signLen,
      short pubKeyStart, short pubKeyLen) {
    //TODO support ES384 and ES512.
    if(alg != SEProvider.ES256) return false;
    ecKeyPair.genKeyPair();
    ECPublicKey key = (ECPublicKey)ecKeyPair.getPublic();
    key.setW(buf, pubKeyStart, pubKeyLen);
    signerWithSha256.init(key, Signature.MODE_VERIFY);
    return signerWithSha256.verify(
        buf, toBeSignedStart, toBeSignedLen,sign, signStart,signLen);
  }
  public Signature getVerifier(byte[] key, short keyStart, short keyLen, short alg, byte mode){
    if(alg != SEProvider.ES256) return null;
    ecKeyPair.genKeyPair();
    ECPublicKey pubKey = (ECPublicKey)ecKeyPair.getPublic();
    pubKey.setW(key, keyStart, keyLen);
    SEProvider.print(key, keyStart, keyLen);
    signerWithSha256.init(pubKey, mode);
    return signerWithSha256;
  }
}
