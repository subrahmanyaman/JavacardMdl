package com.android.javacard.mdl.provision;

import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;

/**
 * This class represents the provisioning aspect of the document. Specifically it stores
 * credential keys and storage key for the document and it is associated with the slot. When
 * provisioning applet reserves the slot for a document, instance of the this class is reserved
 * and using this functionality the provisioning applet will attest and encrypt the ppresentation
 * package, which is being provisioned.
 *
 */
public class Mdoc {
  private AESKey mStorageKey;
  private KeyPair mCredentialKey;
  private boolean mReserved;
  private short mSlotId;
  private boolean mProvisioned;
  private boolean[] mTestCred;
  public Mdoc(short slotId){
    mTestCred = JCSystem.makeTransientBooleanArray((short)1, JCSystem.CLEAR_ON_DESELECT);
    mTestCred[0] = false;
    mSlotId = slotId;
    mCredentialKey = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
    SEProvider.instance().initECKey(mCredentialKey);
    mStorageKey = (AESKey) KeyBuilder.buildKey(
        KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
  }
  public void reserve(){
    mReserved = true;
  }
  public void release(){
    mReserved = false;
  }
  public boolean isReserved(){
    return mReserved;
  }
  public void store(byte[] buf, short start, short len){
    ProvisioningApplet.write(mSlotId, buf, start, len);
  }
  public void resetUsageCount(){
    ProvisioningApplet.resetUsageCount(mSlotId);
  }
  public short getUsageCount(){
    return ProvisioningApplet.getUsageCount(mSlotId);
  }
  public KeyPair getCredentialKey(){
    return mCredentialKey;
  }
  public void create(short size, byte[] scratch, short start, short len){
    SEProvider.initECKey(mCredentialKey);
    mCredentialKey.genKeyPair();
    SEProvider.instance().generateRandomData(scratch, start, (short)32);
    mStorageKey.setKey(scratch, start);
    ProvisioningApplet.createPackage(mSlotId, size);
  }
  public void delete(byte[] scratch, short start, short len) {
    mTestCred[0] = false;
    ECPublicKey pub = ((ECPublicKey)mCredentialKey.getPublic());
    ECPrivateKey priv = ((ECPrivateKey)mCredentialKey.getPrivate());
    priv.clearKey();
    pub.clearKey();
//    short size = pub.getW(scratch,start);
//    Util.arrayFillNonAtomic(scratch, start, size,(byte)0);
//    pub.setW(scratch,start,size);
//    size = priv.getS(scratch,start);
//    Util.arrayFillNonAtomic(scratch, start, size,(byte)0);
//    priv.setS(scratch,start,size);
    mStorageKey.clearKey();
    ProvisioningApplet.deletePackage(mSlotId);
  }
  public void enableTestCred(byte[] scratch, short start, short len) {
    mTestCred[0] = true;
    mStorageKey.clearKey();
    Util.arrayFillNonAtomic(scratch,start,(short) 32, (byte)0);
    mStorageKey.setKey(scratch, start);
  }
  public AESKey getStorageKey() {
    return mStorageKey;
  }
  public void startProvisioning() {
    ProvisioningApplet.startProvisioning(mSlotId);
    mProvisioned = false;
  }
  public void commitProvisioning() {
    ProvisioningApplet.commitProvisioning(mSlotId);
    mProvisioned = true;
  }
  public boolean isProvisioned() {
    return mProvisioned;
  }
  public boolean isTestCredential(){
    return mTestCred[0];
  }
}
