package com.android.javacard.mdl;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
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
import javax.crypto.AEADBadTagException;
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
  public static final short ES256 = 1;
  public static final short ES384 = 2;
  public static final short ES512 = 3;
  private Signature signerWithSha256;
  private KeyPair ecKeyPair;
  private static SEProvider inst;
  private javax.crypto.Cipher mCipher;
  private RandomData mRng;
  public static SEProvider instance(){
    if(inst == null){
      inst = new SEProvider();
      X509CertHandler.init((short)4096);
    }
    return inst;
  }
  private SEProvider(){
    ecKeyPair = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
    signerWithSha256 = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
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
    mRng = RandomData.getInstance(RandomData.ALG_TRNG);
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
    signer.init(key, Signature.MODE_SIGN);
    return signer.sign(
          inputDataBuf, inputDataStart, inputDataLength, outputDataBuf, outputDataStart);
  }

  private static java.security.Key convert(AESKey key){
    byte[] keyBuf = new byte[32];
    byte len = key.getKey(keyBuf, (short)0);
    return new SecretKeySpec(keyBuf, (short)0, len, "AES");
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
    // Create the cipher
    short mode = encrypt ? (short) Cipher.ENCRYPT_MODE : (short) Cipher.DECRYPT_MODE;
    initCipher(key,nonce,start,len, authData, authDataStart, authDataLen, mode);

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

  public void generateRandomData(byte[] tempBuffer, short offset, short length) {
    mRng.nextBytes(tempBuffer, offset, length);
    print(tempBuffer, offset, length);
  }

  public static void print(byte[] buf, short start, short length) {
    StringBuilder sb = new StringBuilder();
    System.out.println("----");
    for (int i = start; i < (start + length); i++) {
      sb.append(String.format("%02X", buf[i]));
    }
    System.out.println(sb);
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
        authDataLen, (short) Cipher.ENCRYPT_MODE);
    // Encrypt
    short len = 0;
    byte[] outputBuf = new byte[mCipher.getOutputSize(secretLen)];
    try {
      if(!justUpdate) {
        len = (short) (mCipher.doFinal(secret, secretStart, secretLen, outputBuf, (short) 0));
      }else{
        len = (short) (mCipher.update(secret, secretStart, secretLen, outputBuf, (short) 0));
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
        authDataLen, (short) Cipher.DECRYPT_MODE);
    // Decrypt
    short len = 0;
    byte[] outputBuf = new byte[mCipher.getOutputSize(encSecretLen)];
    try {
      if(!justUpdate) {
        len = (short) (mCipher.doFinal(encSecret, encSecretStart,
            encSecretLen, outputBuf, (short) 0));
      }else{
        len = (short) (mCipher.update(encSecret, encSecretStart,
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
  public void initCipher(
      AESKey aesKey,
      byte[] nonce,
      short nonceStart,
      short nonceLen,
      byte[] authData,
      short authDataStart,
      short authDataLen,
      short mode){
    //Create the sun jce compliant aes key
    java.security.Key key = convert(aesKey);
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
      mCipher.init(mode, key, spec);
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
