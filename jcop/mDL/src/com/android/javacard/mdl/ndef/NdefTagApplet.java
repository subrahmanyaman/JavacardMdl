package com.android.javacard.mdl.ndef;

import com.android.javacard.mdl.MdlService;
import com.android.javacard.mdl.PresentationApplet;

import javacard.framework.AID;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacardx.apdu.ExtendedLength;

/**
 * This class implements the placeholder NDefTagApplet which is required to exchange Mdl related
 * capability container, ndef files, and handover select message. This applet is just a
 * placeholder because an actual NFC enabled SE may already have similar applet.
 *
 */
public class NdefTagApplet extends Applet implements ExtendedLength {
  public static final byte[] AID_NDEF_TAG_APPLET = {
      (byte) 0xD2, 0x76, 0x00, 0x00, (byte) 0x85, 0x01, 0x01};
  static final short MAX_NDEF_DATA_FILE_SIZE = 1024;
  static final short STATUS_WORD_END_OF_FILE_REACHED = 0x6282;
  static final byte INS_SELECT = ISO7816.INS_SELECT;
  static final byte INS_READ_BINARY = (byte) 0xB0;
  static final short FILE_ID_CAPS_CONTAINER = (short) 0xE103;
  static final short FILE_ID_NDEF_FILE = (short) 0xE104;

  // Hardcoded Capability Container files that points to read only NDEF Data File.
  static final byte[] CAPS_CONTAINER = {
      (byte) 0x00, (byte) 0x0F,  // size of capability container '00 0F' = 15 bytes
      (byte) 0x20,               // mapping version v2.0
      (byte) 0x7F, (byte) 0xFF,  // maximum response data length '7F FF'
      (byte) 0x7F, (byte) 0xFF,  // maximum command data length '7F FF'
      (byte) 0x04, (byte) 0x06,  // NDEF File Control TLV
      (byte) 0xE1, (byte) 0x04,  // NDEF file identifier 'E1 04'
      (byte) 0x7F, (byte) 0xFF,  // maximum NDEF file size '7F FF'
      (byte) 0x00,               // file read access condition (allow read)
      (byte) 0xFF                // file write access condition (do not write)
  };

  // The NDEF Data File is Handover Select Message, which consists of 3 records as follows:
  // 1. Handover Select Record, that consists of Alternative Carrier Record consisting of
  // first a CDR pointing to the "nfc "Carrier Configuration NDEF Record and secondly an Auxiliary
  // Record "mdoc" NDEF record.
  //
  // 2. The "nfc" Carrier Configuration NDEF Record provides three fields record of nfc type, max
  // command size and max response size. This record is pointed by CDR.
  // All the above messages are NDEF encoded and hardcoded, except the part of "mdoc" NDEF
  // record that contains Device engagement data, which is referenced by the fixed offset.
  //
  // 3. The "mdoc" NDEF Record, which contains the CBOR encoded Device Engagement data which is
  // generated by MDL Applet. This data is accessed by this applet using MDL Applet's Shareable
  // interface.
/*
  static final byte[] NDEF_FILE_FIXED_PART = {
      INVALID_VALUE, INVALID_VALUE, // NDEF Data file length - placeholder
      // 1. Handover Select Record - size = 3 + 2 + 17 = 22
      // Refer nfcCalculateHandover in com.android.identity.PresentationHelper
      // NDEF Header
      (byte) 0b10010001, //MB=1, ME=0, CF=0, SR=1, IL=0, TNF= 1 (Well Known Type)
      // Lengths
      (byte) 2, // length of "Hs" type
      (byte) 17, //Size of "Hs" payload
      0x48, 0x73, // // Value of UTF-8 encoded "Hs" type,
      // Payload - Handover Select Record Payload
      // Refer nfcCalculateStaticHandoverSelectPayload in com.android.identity.DataTransferNfc
      0x15, // Major and Minor Version of connection handover specs i.e. 1.5
      // Alternative Carrier Record - only one record
      // NDEF Header
      (byte) 0b11010001, //MB=1, ME=1, CF=0, SR=1, IL=0, TNF= 1 (Well Known Type)
      // Lengths
      (byte) 2, // length of "ac" type
      (byte) 11, //Size of "ac" payload
      0x61, 0x63, // Value of UTF-8 encoded "ac" type,
      // Payload - AC record payload
      // Refer to createNdefRecord method in com.android.identity.DataTransferNfc
      // Header
      0x01, // RFU = 0, CPS = 1 (ACTIVE)
      // CDR
      0x03, // Length of "nfc" configuration record reference chars
      0x6E, 0x66, 0x63, // Value of UTF-8 encoded "nfc" Id
      // Aux Record
      0x01, // Number of auxiliary record is 1 as only "mdoc" is required
      0x04, // Length of "mdoc" record reference chars
      0x6d, 0x64, 0x6f, 0x63, // Value of UTF-8 encoded "mdoc" id.

      // 2. "nfc" Carrier Configuration Record - size = 4 +17 + 9 + 3 = 33
      // Refer to createNdefRecord method in com.android.identity.DataTransferNfc
      // NDEF Header
      (byte) 0b00011010, //MB=0, ME=0, CF=0, SR=1, IL=1, TNF= 2 (MIME)
      // Lengths
      (byte) 17, // length of "iso.org:18013:nfc" type
      (byte) 9, //Size of payload
      (byte) 3, //size of id i.e. "nfc"
      //Value of UTF-8 encoded "iso.org:18013:nfc" type
      0x69, 0x73, 0x6F, 0x2E, 0x6F, 0x72, 0x67, 0x3A, 0x31, 0x38, 0x30, 0x31, 0x33, 0x3A, 0x6E,
      0x66, 0x63,
      0x6E, 0x66, 0x63, // Value of UTF-8 encoded "nfc" Id 21+9
      //Payload Configuration record as defined in ISO18013 - section 8.2.2.2
      0x01, // version
      0x03, // Data length of the max command size
      0x01, // Data type of the max command size
      (byte) ((MAX_BUF_SIZE >> 8) & 0x00FF), (byte) (MAX_BUF_SIZE & 0x00FF), // Max Cmd Size
      0x03, // Data length of the max response size
      0x02, // Data type of the max response size
      (byte) ((MAX_BUF_SIZE >> 8) & 0x00FF), (byte) (MAX_BUF_SIZE & 0x00FF), // Max response Size

      // 3. "mdoc" NDEF Record - start = 33 + 22 + 2= 57
      // Refer nfcCalculateHandover in com.android.identity.PresentationHelper
      // NDEF Header - HEADER OFFSET = PAYLOAD_LEN_OFFSET - 2
      (byte)0b01011100, //MB=0, ME=0, CF=0, SR=1, IL=1, TNF= 4 (External)
      // Lengths
      (byte)30, // length of "iso.org:18013:deviceengagement" type
      //Size of Payload - PAYLOAD_LEN_OFFSET = PAYLOAD OFFSET - MDOC_ID_LEN - MDOC_TYPE_LEN - 2
      INVALID_VALUE,
      (byte)4, //size of id i.e. "mdoc"
      // Type Value - UTF-8 encoded  "iso.org:18013:deviceengagement"
      0x69,0x73,0x6F,0x2E,0x6F,0x72,0x67,0x3A,0x31,0x38,0x30,0x31,0x33,
      0x3A,0x64,0x65,0x76,0x69,0x63,0x65,0x65,0x6E,0x67,0x61,0x67,0x65,
      0x6D,0x65,0x6E,0x74,
      // Id Value - UTF-8 encoded "mdoc"
      0x6d, 0x64, 0x6f, 0x63,
      // Payload - PAYLOAD OFFSET = FIXED PART size
  };
*/
  private short[] mSelectedFile;
  private byte[] mNdefDataFile;
  private AID mAid;
  public static void install(byte[] buf, short off, byte len) {
    // instantiate and initialize the applet
    NdefTagApplet applet = new NdefTagApplet();
    // register the applet
    applet.register();
  }

  public NdefTagApplet(){
    mAid = new AID(PresentationApplet.AID_MDL_DIRECT_ACCESS_APPLET, (short) 0,
        (byte) PresentationApplet.AID_MDL_DIRECT_ACCESS_APPLET.length);
    mNdefDataFile =
        JCSystem.makeTransientByteArray(MAX_NDEF_DATA_FILE_SIZE, JCSystem.CLEAR_ON_DESELECT);
    mSelectedFile = JCSystem.makeTransientShortArray((short)(1), JCSystem.CLEAR_ON_DESELECT);;
  }

  @Override
  public void process(APDU apdu) throws ISOException {
    byte[] buffer = apdu.getBuffer();
    byte ins = buffer[ISO7816.OFFSET_INS];
    if(selectingApplet()) {
      return;
    }
    if(apdu.isSecureMessagingCLA()) {
      ISOException.throwIt(ISO7816.SW_SECURE_MESSAGING_NOT_SUPPORTED);
    }
    // process commands to the applet
    if(apdu.isISOInterindustryCLA()) {
      switch (ins) {
        case INS_SELECT:
          processSelect(apdu);
          break;
        case INS_READ_BINARY:
          processReadBinary(apdu);
          break;
        default:
          ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
      }
    } else {
      ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
    }
  }
  // Refer nfcEngagementHandleSelectFile in com.android.identity.PresentationHelper
  private void processSelect(APDU apdu){
    byte[] buf = apdu.getBuffer();
    // Validate P1 and P2
    if(buf[ISO7816.OFFSET_P1] != (byte)0x00 && buf[ISO7816.OFFSET_P2] != (byte)0x0C) {
      ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
    }
    // File ID will always be two bytes
    if(buf[ISO7816.OFFSET_LC] != 2) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }

    // Only support two file ids
    switch(Util.getShort(buf, ISO7816.OFFSET_CDATA)) {
      case FILE_ID_CAPS_CONTAINER:
        mSelectedFile[0] = FILE_ID_CAPS_CONTAINER;
        break;
      case FILE_ID_NDEF_FILE:
        // Everytime Ndef File is selected new device Engagement data must be generated and hence
        // new Ndef data file needs to be generated.
        MdlService mdl = (MdlService) JCSystem.getAppletShareableInterfaceObject(mAid,
            MdlService.SERVICE_ID);
        short payloadLength = mdl.getHandoverSelectMessage(mNdefDataFile, (short) 2);
        // Set the length of the NDEF File which includes payload and preceding two bytes for
        // the file length
        Util.setShort(mNdefDataFile, (short) 0, (short) (payloadLength + 2));
        mSelectedFile[0] = FILE_ID_NDEF_FILE;
        break;
      default:
        ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
        break;
    }
  }

  // Refer nfcEngagementHandleReadBinary in com.android.identity.PresentationHelper
  private void processReadBinary(APDU apdu) {
    byte[] buf = apdu.getBuffer();

    if(buf[ISO7816.OFFSET_LC] == 0){
      if((short)buf.length < 7){
        ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
      }
    }
    short offset = Util.getShort(buf, ISO7816.OFFSET_P1);
    byte[] file = mSelectedFile[0] == FILE_ID_NDEF_FILE ? mNdefDataFile : CAPS_CONTAINER;

    short contentLen = Util.getShort(file,(short)0);
    if (offset < 0 || offset >= contentLen) {
      ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
    }
    short size = apdu.setOutgoing();

    // (short)(offset + size) can become negative if it is > 32KiB
    if( (short)(offset + size) < 0){
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    if((short)(offset + size) > contentLen) {
      ISOException.throwIt(STATUS_WORD_END_OF_FILE_REACHED);
    }
    apdu.setOutgoingLength(size);
    apdu.sendBytesLong(file, offset, size);
  }

}