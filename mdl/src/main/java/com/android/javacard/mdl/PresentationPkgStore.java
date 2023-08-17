package com.android.javacard.mdl;

/**
 * Thi is the implementation of presentation package store shareable interface and it is
 * instantiated by the presentation applet. The provisioning applet uses this shareable interafce
 * to provision the data.
 */
public class PresentationPkgStore implements MdlPresentationPkgStore{
  private MdocPresentationPkg[] mPackages;
  private static PresentationPkgStore mInstance;
  private static short mMaxSlots;
  private static short mMaxPkgSize;
  private PresentationPkgStore(){
    mInstance = this;
  }
  public static PresentationPkgStore instance(){
    if(mInstance == null){
      mInstance = new PresentationPkgStore();
    }
    return mInstance;
  }
  public void configure(short maxSlots, byte preAllocatedDocCount, short maxDocumentSize){
    mMaxSlots = maxSlots;
    mMaxPkgSize = maxDocumentSize;
    mPackages = new MdocPresentationPkg[maxSlots];
    for(byte i =0 ; i < maxSlots; i++) {
      mPackages[i] = new MdocPresentationPkg();
      if(preAllocatedDocCount > 0){
        mPackages[i].allocMem(maxDocumentSize);
        mPackages[i].setPreAllocated();
        preAllocatedDocCount--;
      }
    }
  }
  @Override
  public MdocPresentationPkg findPackage(byte[] id, short start, short len){
    for(byte i = 0; i < mPackages.length; i++){
      if(mPackages[i].isMatching(id, start, len)){
        return mPackages[i];
      }
    }
    return null;
  }
  @Override
  public short getMaxSlotCount() {
    return mMaxSlots;
  }
  @Override
  public MdocPresentationPkg getPackage(byte slot) {
    return mPackages[slot];
  }
  @Override
  public short getMaxPackageSize(){
    return mMaxPkgSize;
  }

  @Override
  public void write(short slotId, byte[] buf, short start, short len) {
    mPackages[slotId].write(buf, start,len);
  }
  @Override
  public void resetUsageCount(short slotId) {
    mPackages[slotId].resetUsageCount();
  }
  @Override
  public short getUsageCount(short slotId) {
    return mPackages[slotId].getUsageCount();
  }
  @Override
  public void createPackage(short slotId, short size) {
    mPackages[slotId].create(size);
  }
  @Override
  public void deletePackage(short slotId) {
    mPackages[slotId].delete();
  }
  @Override
  public void startProvisioning(short slotId) {
    mPackages[slotId].startProvisioning();
  }
  @Override
  public void commitProvisioning(short slotId) {
    mPackages[slotId].commitProvisioning();
  }
}
