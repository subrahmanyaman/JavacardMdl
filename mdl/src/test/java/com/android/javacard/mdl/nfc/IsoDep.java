package com.android.javacard.mdl.nfc;

import com.android.javacard.mdl.MdlTest;
import com.android.javacard.mdl.jcardsim.SEProvider;
import java.io.IOException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

public class IsoDep {
  private static final String TAG = "NFC";
  boolean mIsConnected;
  int mTimeout;

  IsoDep() {
    mTimeout = 36000000;
  }

  public IsoDep getTag() {
    return this;
  }

  void checkConnected() {
  }

  public boolean isConnected() {
   return true;
  }

  public void connect() throws IOException {
    // This method actually establishes/connects to correct RF Interface in NCI.
    // Nothing to be done for the unit test cases - in rel device this will be
    // done by BasicTechnologyTag class using the TagService implemented by the NfcService
    MdlTest.connectTag();
  }

  public void reconnect() throws IOException {
    // Same as connect
    MdlTest.reconnectTag();
  }

  public void close() throws IOException {
    // Same as connect
    MdlTest.closeTag();
  }

  int getMaxTransceiveLengthInternal() {
    //This comes from the NDEF File. Currently, just hard coding it for unit testcases.
    return MdlTest.maxTransceiveLength();
  }
  // This is the main adaptation for JUnit test case
  byte[] transceive(byte[] data, boolean raw) throws Exception {
    checkConnected();
    CommandAPDU apdu = MdlTest.getCommandApdu(data);
    ResponseAPDU resp = MdlTest.transmitCommand(apdu);
    SEProvider.print(apdu.getBytes(), (short)0, (short) apdu.getBytes().length);
    return resp.getBytes();
  }


  /** @hide */
  public static final String EXTRA_HI_LAYER_RESP = "hiresp";
  /** @hide */
  public static final String EXTRA_HIST_BYTES = "histbytes";

  private byte[] mHiLayerResponse = null;
  private byte[] mHistBytes = null;

  public void setTimeout(int timeout) {
    mTimeout = timeout;
  }

  public int getTimeout() {
    return mTimeout;
   }

  public byte[] getHistoricalBytes() {
    return mHistBytes;
  }

  public byte[] getHiLayerResponse() {
    return mHiLayerResponse;
  }

  public byte[] transceive(byte[] data) throws Exception {
    return transceive(data, true);
  }

  public int getMaxTransceiveLength() {
    return getMaxTransceiveLengthInternal();
  }

  public boolean isExtendedLengthApduSupported() {
    return MdlTest.isExtendedLengthApduSupported();
  }
}
