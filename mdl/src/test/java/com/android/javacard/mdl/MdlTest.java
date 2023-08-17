package com.android.javacard.mdl;

import com.android.javacard.mdl.nfc.DataRetrievalAddress;
import com.android.javacard.mdl.nfc.NdefMessage;
import com.licel.jcardsim.smartcardio.CardSimulator;
import java.util.List;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

public class MdlTest
{
  public static CardSimulator simulator = null;
  public static byte[] mData = null;
  public static void connectTag(){}
  public static void reconnectTag(){}
  public static void closeTag(){}
  public static int maxTransceiveLength(){return 1024;}

  // For JCardSim and JCOP if either Lc is extended or Le is extended we will have to use
  // extended APDU.
  // Refer buildApdu method in DataTransportNfc class - which adds extra byte when command is not
  // extended and expected response is extended.
  // i.e. LC = 0 or < 256 and LE > 256 - in other words apdu.length = 8 + Lc due to this extra
  // byte and this fails CommandAPDU creation.
  // The following method fixes this by converting this case into 4E or 2E properly.

  public static CommandAPDU getCommandApdu(byte[] apdu){
    /*
    byte cla = apdu[ISO7816.OFFSET_CLA];
    byte ins = apdu[ISO7816.OFFSET_INS];
    byte p1 = apdu[ISO7816.OFFSET_P1];
    byte p2 = apdu[ISO7816.OFFSET_P2];

    boolean extApdu =
        (apdu[ISO7816.OFFSET_LC] == 0 && (short)(apdu.length) >= ISO7816.OFFSET_EXT_CDATA);
    short len = extApdu ? Util.getShort(apdu, (short) (ISO7816.OFFSET_LC + 1))
        : apdu[ISO7816.OFFSET_LC];
    short cdataOff = extApdu ? ISO7816.OFFSET_EXT_CDATA : ISO7816.OFFSET_CDATA;
    short end = (short) (cdataOff + len);
    short ne = 0;
    // if extended apdu
    if(extApdu && (short)apdu.length == (short) (end + 2)){
      ne = Util.getShort(apdu,end);
    }else if(!extApdu && (short)apdu.length == (short) (end + 1)){ // if not extended apdu
      ne = apdu[end];
    }else if((short)apdu.length == (short) (end + 3)){ // if le is extended
      end++;
      extApdu = true;
      ne = Util.getShort(apdu,end);
    }
    // If the apdu must be extended and the apdu[ISO7816.OFFSET_LC] is not zero then convert the
    // apdu in extended apdu.
    if (extApdu && apdu[ISO7816.OFFSET_LC] != 0){
      byte[] origApdu = apdu;
      apdu = new byte[apdu.length + 2];
      Util.arrayCopyNonAtomic(origApdu, (short)0, apdu, (short)0, ISO7816.OFFSET_LC);
      Util.arrayCopyNonAtomic(origApdu, ISO7816.OFFSET_LC, apdu,
          (short) (ISO7816.OFFSET_EXT_CDATA - 1), (short) (origApdu.length - ISO7816.OFFSET_LC));
      cdataOff = ISO7816.OFFSET_EXT_CDATA;
    }
    return new CommandAPDU(cla, ins, p1, p2, apdu, cdataOff, len, ne);
     */
    int l1 = apdu[4] & 255;
    if(apdu.length == 8 + l1) { // command is not extended and response is extended.
      if (l1 == 0) { // covert into 2E by removing extra byte
        byte[] newApdu = new byte[7];
        Util.arrayCopyNonAtomic(apdu, (short) 0, newApdu, (short) 0, (short) 4);
        newApdu[5] = apdu[6];
        newApdu[6] = apdu[7];
        apdu = newApdu;
      } else { // convert to 4E by making it the extended apdu
        byte[] newApdu = new byte[9 + l1];
        Util.arrayCopyNonAtomic(apdu, (short) 0, newApdu, (short) 0, (short) 4);
        newApdu[6] = (byte) l1;
        Util.arrayCopyNonAtomic(apdu, (short) 5, newApdu, (short) 7, (short) l1);
        newApdu[7 + l1] = apdu[6 + l1];
        newApdu[8 + l1] = apdu[7 + l1];
        apdu = newApdu;
      }
    }
    return new CommandAPDU(apdu);
  }

  public static ResponseAPDU transmitCommand(CommandAPDU apdu){
    return simulator.transmitCommand(apdu);
  }

  public static boolean isExtendedLengthApduSupported(){
    return true;
  }

  public static String getNdefTechName() {
    return "NDEF";
  }

  public static NdefMessage getCachedNdefMessage() {
    try {
      return new NdefMessage(mData);
    } catch (Exception e) {
      e.printStackTrace();
    }
    return null;
  }

  public static String getIosDepTechName() {
    return "ISO_DEP";
  }
  public static List<DataRetrievalAddress> mAddresses;
  public static void setAddresses(List<DataRetrievalAddress> addresses) {
    mAddresses = addresses;
  }

}
