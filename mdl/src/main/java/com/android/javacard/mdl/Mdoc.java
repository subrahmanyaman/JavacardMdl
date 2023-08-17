package com.android.javacard.mdl;

import com.android.javacard.mdl.jcardsim.SEProvider;
import javacard.framework.Util;
import javacard.security.AESKey;
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
  public Mdoc(short slotId){
    mSlotId = slotId;
    mCredentialKey = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
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
    mCredentialKey.genKeyPair();
    SEProvider.instance().generateRandomData(scratch, start, (short)32);
    mStorageKey.setKey(scratch, start);
    ProvisioningApplet.createPackage(mSlotId, size);
  }
  public void delete() {
    mStorageKey.clearKey();
    mCredentialKey.getPublic().clearKey();
    mCredentialKey.getPrivate().clearKey();
    ProvisioningApplet.deletePackage(mSlotId);
  }
  public void enableTestCred(byte[] scratch, short start, short len) {
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
}
