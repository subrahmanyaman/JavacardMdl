package com.android.javacard.mdl.presentation;

import javacard.framework.Shareable;

/**
 * This interface declares the methods required to implement presentation package store. The
 * presentation packages can be of any doc type. It stores one package per slot. Number of slots
 * are specified during install time.
 * This interface can be implemented as shareable interface. Presentation Applet and Provisioning
 * applet both uses this to share the data,
 *
 */
public interface MdlPresentationPkgStore extends Shareable {
  public static final byte SERVICE_ID = 2;
  MdocPresentationPkg findPackage(byte[] id, short start, short len);
  short getMaxSlotCount();
  MdocPresentationPkg getPackage(byte slot);
  short getMaxPackageSize();
  void write(short slotId, byte[] buf, short start, short len);
  void resetUsageCount(short slotId);
  short getUsageCount(short slotId);
  void createPackage(short slotId, short size);
  void deletePackage(short slotId);
  void startProvisioning(short slotId);
  void commitProvisioning(short slotId);
}
