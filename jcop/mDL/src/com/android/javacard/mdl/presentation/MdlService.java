package com.android.javacard.mdl.presentation;

import javacard.framework.Shareable;

/**
 * This interface provides method for Ndef Tag Applet to get the handover select message from the
 * mdl service i.e. PresentationApplet. This is required because part of the handover select
 * message is ephemeral and thus dynamically generated at the runtime.
 */
public interface MdlService extends Shareable {
  public static final byte SERVICE_ID = 1;
  short getHandoverSelectMessage(byte[] buf, short start);

}
