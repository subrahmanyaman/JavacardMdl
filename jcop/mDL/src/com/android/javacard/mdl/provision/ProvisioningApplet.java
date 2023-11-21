package com.android.javacard.mdl.provision;

import com.android.javacard.mdl.presentation.MdlPresentationPkgStore;

import javacard.framework.AID;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacardx.apdu.ExtendedLength;

public class ProvisioningApplet extends Applet implements ExtendedLength {
  // TODO Change this applet id if required
//  public static final byte[] DIRECT_ACCESS_PROVISIONING_APPLET_ID = {
//      (byte)0xA0, 0x00, 0x00, 0x04, 0x76, 0x57, 0x56, 0x52, 0x43, 0x4F, 0x52, 0x45,0x30,
//      0x00, 0x01, 0x01};
  public static final byte[] DIRECT_ACCESS_PROVISIONING_APPLET_ID = {
      (byte) 0xA0, 0x00, 0x00, 0x02, 0x48, 0x04, 0x00, 0x01, 0x01, 0x01};
  public static final byte[] AID_MDL_DIRECT_ACCESS_APPLET = {
      (byte) 0xA0, 0x00, 0x00, 0x02, 0x48, 0x04, 0x00};
  public final static short MAX_MDOC_SIZE = (short) 0x7FFF;

  private static final byte CTX_CMD = 0;
  private static final byte CTX_STATUS = 1;
  private static final byte CTX_SELECTED_DOCUMENT = 2;
  private static final byte SELECT_MDOC = 0;
  private static final byte MAX_DOCUMENTS_SLOTS = 1;
  private static final short MAX_BUFFER_SIZE = (short) 2048;
  private static final byte MAX_CONTEXT_SIZE = (short) 16;
  private static final byte MAX_TEMP_BUF_SIZE = (short) 32;
  public final static byte INS_ENVELOPE = (byte) 0xC3;
  public final static byte INS_GET_RESPONSE = (byte) 0xC0;
  public final static byte INS_PROVISION_DATA = (byte) 0x01;
  public final static byte TAG_ATT_PUB_KEY_CERT = 0x01;
  public final static byte TAG_ATT_PRIV_KEY = 0x02;
  /**
   * CBOR Map = { 0:CBOR uint version, - MS byte major and LS byte minor versions respectively.
   * 1:CBOR uint maxSlots, 2:CBOR uint maxDocSize, 3:CBOR uint minExtendedApduBufSize, 4: CBOR uint
   * number of pre-allocated slots, - each slot equal to maxDocSize. }
   */
  private static final byte[] INFORMATION = {
      (byte) (MdlSpecifications.CBOR_MAP | (byte) 5),
      0, MdlSpecifications.CBOR_UINT16_LENGTH, 0x10, 0x00,
      1, MAX_DOCUMENTS_SLOTS,
      2, MdlSpecifications.CBOR_UINT16_LENGTH, 0x7F, (byte) 0xFF,
      3, MdlSpecifications.CBOR_UINT16_LENGTH, 0x10, (byte) 0x00,
      4, MAX_DOCUMENTS_SLOTS,
  };
  // Commands
  public static final byte CMD_MDOC_CREATE = 1;
  public static final byte CMD_MDOC_LOOKUP = 3;
  public static final byte CMD_MDOC_SWAP_IN = 6;
  public static final byte CMD_MDOC_CREATE_PRESENTATION_PKG = 7;
  public static final byte CMD_MDOC_DELETE_CREDENTIAL = 8;
  public static final byte CMD_MDOC_PROVISION_DATA = 9;
  public static final byte CMD_MDOC_SELECT = 10;
  public static final byte CMD_MDOC_GET_INFORMATION = 11;
  private static Mdoc[] mDocuments;
  private static MdlPresentationPkgStore mPkgStore;
  //private AID mPkgStoreAid;


  private final CBORDecoder mDecoder;
  private final CBOREncoder mEncoder;
  private final short[] mContext;
  private final short[] mTemp;
  private static byte[] mScratch;
  private static byte[] heap;
  private final Object[] mSelectedDocument;
  KeyPair mAuthKey;
  SEProvider mSEProvider;

  private ProvisioningApplet() {
    mSEProvider = SEProvider.instance();
    heap = JCSystem.makeTransientByteArray(MAX_BUFFER_SIZE, JCSystem.CLEAR_ON_DESELECT);
    mDecoder = new CBORDecoder();
    mEncoder = new CBOREncoder();
    mContext = JCSystem.makeTransientShortArray(MAX_CONTEXT_SIZE, JCSystem.CLEAR_ON_DESELECT);
    mTemp = JCSystem.makeTransientShortArray(MAX_TEMP_BUF_SIZE, JCSystem.CLEAR_ON_DESELECT);
    mSelectedDocument = JCSystem.makeTransientObjectArray((short) 1, JCSystem.CLEAR_ON_DESELECT);
    mAuthKey = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
    mSEProvider = SEProvider.instance();
    mSEProvider.initECKey(mAuthKey);
//    mPkgStoreAid = new AID(AID_MDL_DIRECT_ACCESS_APPLET, (short) 0,
//        (byte) AID_MDL_DIRECT_ACCESS_APPLET.length);
//    mPkgStoreAid = 
//        JCSystem.lookupAID(AID_MDL_DIRECT_ACCESS_APPLET, (short) 0, (byte) AID_MDL_DIRECT_ACCESS_APPLET.length);
  }
  public static void install(byte[] bArray, short bOffset, byte bLength) {
    mScratch = JCSystem.makeTransientByteArray(MAX_BUFFER_SIZE, JCSystem.CLEAR_ON_DESELECT);
    new ProvisioningApplet().register();
    AID aid = new AID(AID_MDL_DIRECT_ACCESS_APPLET, (short) 0,
      (byte) AID_MDL_DIRECT_ACCESS_APPLET.length);
    mPkgStore = (MdlPresentationPkgStore) JCSystem.getAppletShareableInterfaceObject(aid,
        (byte) 2 /*MdlPresentationPkgStore.SERVICE_ID */);
    configureStore();

  }

  public static void configureStore(){
    short maxSlots = mPkgStore.getMaxSlotCount();
    mDocuments = new Mdoc[maxSlots];
    for(byte i =0 ; i < maxSlots; i++) {
      mDocuments[i] = new Mdoc(i);
   }
  }

  public static void createDocument(Mdoc doc, short size, boolean testCred,
      byte[] scratch, short start, short len){
    doc.reserve();
    doc.create(size, scratch, start, len);
    if(testCred) {
      doc.enableTestCred(scratch,start,len);
    }
  }

  public static void destroyDocument(Mdoc doc){
    doc.release();
    doc.delete(mScratch, (short)0, (short) mScratch.length);
  }

  public static Mdoc findDocument(byte slot){
    return mDocuments[slot];
  }

  public static short getMaxSlots(){
    return mPkgStore.getMaxSlotCount();
  }

  public static short getMaxDocumentSize(){
    return mPkgStore.getMaxPackageSize();
  }

  public static void write(short slotId, byte[] buf, short start, short len) {
    mPkgStore.write(slotId, buf, start, len);
  }

  public static void resetUsageCount(short slotId) {
    mPkgStore.resetUsageCount(slotId);
  }

  public static short getUsageCount(short slotId) {
    return mPkgStore.getUsageCount(slotId);
  }

  public static void createPackage(short slotId, short size) {
    mPkgStore.createPackage(slotId, size);
  }

  public static void deletePackage(short slotId) {
    mPkgStore.deletePackage(slotId);
  }

  public static void startProvisioning(short slotId) {
    mPkgStore.startProvisioning(slotId);
  }

  public static void commitProvisioning(short slotId) {
    mPkgStore.commitProvisioning(slotId);
  }

  @Override
  public void deselect() {
    reset();
  }

  public void reset() {
    mSelectedDocument[0] = null;
    clearShortArray(mContext);
    clearShortArray(mTemp);
    Util.arrayFillNonAtomic(mScratch, (short) 0, (short) mScratch.length, (byte) 0);
    Util.arrayFillNonAtomic(heap, (short) 0, (short) heap.length, (byte) 0);
  }

  private void clearShortArray(short[] arr) {
    for (short i = 0; i < (short) arr.length; i++) {
      arr[i] = 0;
    }
  }
  
  @Override
  public boolean select() {
    return true;
  }
  

  @Override
  public void process(APDU apdu) {
    byte[] buffer = apdu.getBuffer();
    if (selectingApplet()) {
      return;
    }
    if (apdu.isSecureMessagingCLA()) {
      ISOException.throwIt(ISO7816.SW_SECURE_MESSAGING_NOT_SUPPORTED);
    }
    // process commands to the applet
    if (apdu.isISOInterindustryCLA()) {
      switch (buffer[ISO7816.OFFSET_INS]) {
        case INS_ENVELOPE:
          processEnvelope(apdu);
          break;
        case INS_GET_RESPONSE:
          processGetResponse(apdu);
          break;
        case INS_PROVISION_DATA:
          processProvisionData(apdu);
          break;
        default:
          ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
      }
    }
  }

  private void processProvisionData(APDU apdu) {
    byte[] buf = apdu.getBuffer();
    if(buf[ISO7816.CLA_ISO7816] != 0 || buf[ISO7816.OFFSET_P1] != 0 || buf[ISO7816.OFFSET_P2] != 0){
      ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
    }
    short recvLen = apdu.setIncomingAndReceive();
    short dataOffset = apdu.getOffsetCdata();
    if (dataOffset != ISO7816.OFFSET_EXT_CDATA){
      ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
    }
    short index = 0;
    short dataLen = apdu.getIncomingLength();
    while (recvLen > 0 && (index < dataLen)) {
      Util.arrayCopyNonAtomic(buf, dataOffset, mScratch, index, recvLen);
      index += recvLen;
      recvLen = apdu.receiveBytes(dataOffset);
    }
    index = 0;
    // Store attestation
    X509CertHandler.clearAttestationKey();
    while(index < dataLen ){
      short tag = Util.getShort(mScratch, index);
      index += 2;
      short len = Util.getShort(mScratch, index);
      index += 2;
      switch(tag){
        case TAG_ATT_PUB_KEY_CERT:
          X509CertHandler.storeAttestationPublicKeyCert(mScratch, index, len);
          break;
        case TAG_ATT_PRIV_KEY:
          X509CertHandler.storeAttestationPrivateKey(mScratch, index, len);
          break;
        default:
          ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
          break;
      }
      index += len;
    }
  }
  
  public short receiveIncoming(APDU apdu) {
    byte[] srcBuffer = apdu.getBuffer();
    short recvLen = apdu.setIncomingAndReceive();
    short srcOffset = apdu.getOffsetCdata();
    // TODO add logic to handle the extended length buffer. In this case the memory can be reused
    //  from extended buffer.
    short bufferLength = apdu.getIncomingLength();
    if (bufferLength == 0) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    short index = 0;
    while (recvLen > 0 && ((short) index < bufferLength)) {
      Util.arrayCopyNonAtomic(srcBuffer, srcOffset, heap, index, recvLen);
      index += recvLen;
      recvLen = apdu.receiveBytes(srcOffset);
    }
    return bufferLength;
  }

  private void processEnvelope(APDU apdu) {
    // receive bytes into mBuffer
    byte[] buf = apdu.getBuffer();
    if (buf[ISO7816.CLA_ISO7816] != 0x10 && buf[ISO7816.CLA_ISO7816] != 0x00) {
      ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
    }
//    apdu.setIncomingAndReceive();
//    short len = apdu.getIncomingLength();
//    if (len == 0) {
//      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
//    }
    receiveIncoming(apdu);
    handleCommand(apdu);
    if ((short) (mContext[CTX_STATUS] & (short) 0xFF00) == ISO7816.SW_BYTES_REMAINING_00) {
      ISOException.throwIt(mContext[CTX_STATUS]);
    } else {
      reset();
    }
  }

  private void processGetResponse(APDU apdu) {
    byte[] buf = apdu.getBuffer();
    if (buf[ISO7816.CLA_ISO7816] != 0x00) {
      ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
    }
    apdu.setIncomingAndReceive();
    short len = apdu.getIncomingLength();
    if (len == 0) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    short status = sendNextChunk(apdu);
    if (status == ISO7816.SW_NO_ERROR) {
      reset();
    } else if ((short) (status & (short) 0xFF00) == ISO7816.SW_BYTES_REMAINING_00) {
      ISOException.throwIt(status);
    }
  }

  private void handleCommand(APDU apdu) {
    byte[] buf = apdu.getBuffer();
    short len = apdu.getIncomingLength();
    short start = apdu.getOffsetCdata();
    if (buf[ISO7816.OFFSET_P1] != 0 || buf[ISO7816.OFFSET_P2] != 0) {
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
    }
    if (len < 2) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }

    // Applet handles one command at a time. CTX gets cleared when a command completes.
    // handle if it is an mdoc credential command.
    if (!handleMdocCommands(Util.getShort(buf, start), apdu, heap, (short) 2,
        len)) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
    //else if (other credential commands)

  }

  private boolean handleMdocCommands(short cmd,APDU apdu, byte[] buf, short start, short len) {
    switch (cmd) {
      case CMD_MDOC_CREATE: {
        /**
         * [
         *   byte slot,
         *   byte testCredential,
         *   short osVersionLen,
         *   byte[] osVersion,
         *   short osPatchLevelLen,
         *   byte[] osPatchLevel,
         *   short challengeLen,
         *   byte[] challengeLen,
         *   short notBeforeLen,
         *   byte[] notBefore (ASN1),
         *   short notAfterLen,
         *   byte[] notAfter (ASN1),
         *   short creationDateTimeLen,
         *   byte[] creationDateTime (milliseconds),
         *   short attAppIdLen,
         *   byte[] attAppId,
         *   short testCredKeyLen,
         *   byte[] testCredKey,
         * ]
         *
         */
        if(buf.length < MAX_BUFFER_SIZE){ // The buffer must be extended length.
          ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        byte slot = buf[start++];
        byte testCredential = buf[start++];
        short osVersionLen = Util.getShort(buf, start);
        start += 2;
        short osVersionStart = start;
        start += osVersionLen;
        short osPatchLevelLen = Util.getShort(buf, start);
        start += 2;
        short osPatchLevelStart = start;
        start += osPatchLevelLen;
        short challengeLen = Util.getShort(buf, start);
        start += 2;
        short challengeStart = start;
        start += challengeLen;
        short notBeforeLen = Util.getShort(buf, start);
        start += 2;
        short notBeforeStart = start;
        start += notBeforeLen;
        short notAfterLen = Util.getShort(buf, start);
        start += 2;
        short notAfterStart = start;
        start += notAfterLen;
        short creationDateTimeLen = Util.getShort(buf, start);
        start += 2;
        short creationDateTimeStart = start;
        start += creationDateTimeLen;
        short attAppIdLen = Util.getShort(buf, start);
        start += 2;
        short attAppIdStart = start;
        start += attAppIdLen;
        short payLoadLength = start;//(short) (start - ISO7816.OFFSET_EXT_CDATA);
        handleCreateMdocCred(apdu, slot, testCredential == 1,
            osVersionStart, osVersionLen,
            osPatchLevelStart, osPatchLevelLen,
            challengeStart, challengeLen,
            notBeforeStart, notBeforeLen,
            notAfterStart, notAfterLen,
            creationDateTimeStart, creationDateTimeLen,
            attAppIdStart, attAppIdLen, payLoadLength);
        break;
      }
      case CMD_MDOC_SELECT:
        /**
         * [
         *   byte slot
         * ]
         */
        handleSelectMdoc(buf[start]);//slot
        break;
      case CMD_MDOC_CREATE_PRESENTATION_PKG:{
        /**
         * [
         *   byte slot,
         *   short notBeforeLen, byte[] notBefore,
         *   short notAfterLen, byte[] notAfter
         * ]
         */
        if(buf.length < MAX_BUFFER_SIZE){ // The buffer must be extended length.
          ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        byte slot = buf[start++];
        Mdoc doc = findDocument(slot);
        if (doc == null) {
          ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        short notBeforeLen = Util.getShort(buf, start);
        start += 2;
        short notBeforeStart = start;
        start += notBeforeLen;
        short notAfterLen = Util.getShort(buf, start);
        start += 2;
        short notAfterStart = start;
        start += notAfterLen;
        short testDevAuthPrivateKeyLen = 0;
        short testDevAuthPrivateKeyStart = 0; // TODO assign invalid value.
        short testDevAuthPublicKeyStart = 0;
        short testDevAuthPublicKeyLen = 0;
        if (doc.isTestCredential()) {
          testDevAuthPrivateKeyLen = Util.getShort(buf, start);
          start += 2;
          testDevAuthPrivateKeyStart = start;
          start += testDevAuthPrivateKeyLen;
          testDevAuthPublicKeyLen = Util.getShort(buf, start);
          start += 2;
          testDevAuthPublicKeyStart = start;
          start += testDevAuthPublicKeyLen;
        }
        short payLoadLength = start;//(short) (start - ISO7816.OFFSET_EXT_CDATA);
        handleCreateAuthKeys(apdu, slot,notBeforeStart, notBeforeLen, notAfterStart, notAfterLen,
            testDevAuthPublicKeyStart, testDevAuthPublicKeyLen,
            testDevAuthPrivateKeyStart, testDevAuthPrivateKeyLen, payLoadLength);
        break;
      }
      case CMD_MDOC_LOOKUP:
        /**
         * [
         *   byte slot
         * ]
         */
        handleLookUpCredential(buf[start]);//slot
        break;
      case CMD_MDOC_DELETE_CREDENTIAL:
        /**
         * [
         *   byte slot
         * ]
         */
        handleDeleteCredential(buf[start]);//slot
        break;
      case CMD_MDOC_GET_INFORMATION: {
        /**
         * [
         *   byte slot
         * ]
         * or nothing
         */
        byte slot = (len > 0) ? buf[start] : (byte) -1;
        handleGetInformation(apdu, slot);
        break;
      }
      case CMD_MDOC_PROVISION_DATA: {
        /**
         * [
         *   byte slot, byte op,
         *   short provDataLen, byte[] provDataLen
         */
        byte slot = buf[start++];
        byte op = buf[start++];
        mDecoder.init(buf, start, len);
        len = mDecoder.readMajorType(CBORBase.TYPE_BYTE_STRING);
        handleProvisionData(apdu, slot, op, mDecoder.getCurrentOffset(), len); // Encrypted data.
      }
      break;

      case CMD_MDOC_SWAP_IN: {
        /**
         * [
         *   byte slot, byte op,
         *   short enc_data_len, byte[] encData
         */
        byte slot = buf[start++];
        byte op = buf[start++];
        mDecoder.init(buf, start, len);
        len = mDecoder.readMajorType(CBORBase.TYPE_BYTE_STRING);
        handleSwapInMdoc(apdu,
            slot,op, mDecoder.getCurrentOffset(), len); //Encrypted data.
      }
      break;
      default:
        return false;
    }
    return true;
  }

  public static final byte BEGIN = 0;
  public static final byte UPDATE = 1;
  public static final byte FINISH = 2;

  /**
   * This command can be used for starting, updating and finishing provision. This is indicated by
   * the op parameter. In this operation the input data is in clear text, and it is returned
   * encrypted. It is not stored into the memory. The input data is validated i.e. valid cbor and
   * mdoc values.
   */
  private void handleProvisionData(APDU apdu, byte slot, byte op, short start,
      short len) {
    Mdoc doc = findDocument(slot);
    if (doc == null) {
      ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
    }
    byte[] buf = heap;//apdu.getBuffer();
    if (op == BEGIN) {
      // Begin uses the data it decrypts it and then re encrypts it such that more data can be
      // encrypted and added using update operation incrementally.
      // Extract the nonce and then decrypt the data - then re-encrypt it.
      // First 12 bytes will be nonce
      short encDataStart = (short)(start + SEProvider.AES_GCM_NONCE_LENGTH);
      short encDataLen = (short)(len - SEProvider.AES_GCM_NONCE_LENGTH);
      // Credential public key is the auth data - copy to scratch
      short credKeyLen = ((ECPublicKey)doc.getCredentialKey().getPublic()).getW(mScratch,
          (short)0);
      mSEProvider.beginAesGcmOperation(
          doc.getStorageKey(), false,
          buf, start, SEProvider.AES_GCM_NONCE_LENGTH,
          mScratch, (short)0, credKeyLen);

      // decrypt data - the decrypted data will be in scratch buffer. Scratch will be sufficiently
      // large to hold slightly greater than 64 bytes of the data.
      short size = mSEProvider.doAesGcmOperation(
          buf, encDataStart,encDataLen,
          mScratch, (short) 0,  false);

      // Validate the decrypted data - array of 2 elements, where first element is byte string
      // and second must be CBOR encoded null - i.e. empty presentation package
      mDecoder.init(mScratch, (short)0, size);
      if(mDecoder.readMajorType(CBORBase.TYPE_ARRAY) != 2){
        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
      }
      if(mDecoder.getMajorType() != CBORBase.TYPE_BYTE_STRING){
        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
      }
      mDecoder.skipEntry();
      if(mDecoder.getRawByte() != CBORBase.ENCODED_NULL){
        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
      }
      //Now, current offset in decoded stream is pointing to credential data start point, so don't
      // skip one byte. i.e. don't perform mDecoder.increaseOffset((short) 1);
      short decryptedDataLen = mDecoder.getCurrentOffset();

      // Copy the decrypted data back to buf. So now 'encDataStart' will point to
      // array of two elements and 'start' will point to start of new nonce.
      // We do not include encoded null value i.e. one less than decrypted data length.
      Util.arrayCopyNonAtomic(mScratch, (short)0, buf, encDataStart, decryptedDataLen);

      // Now start new encryption - regenerate the nonce.
      mSEProvider.generateRandomData(buf, start, SEProvider.AES_GCM_NONCE_LENGTH);

      credKeyLen = ((ECPublicKey)doc.getCredentialKey().getPublic()).getW(mScratch,
          (short)0);
      mSEProvider.beginAesGcmOperation(
          doc.getStorageKey(), true,
          buf, start, SEProvider.AES_GCM_NONCE_LENGTH,
          mScratch, (short)0, credKeyLen);

      // We are now ready to add credential data and encrypt it which will come in update and
      // finish calls.
      // Encrypt the current data. The encrypted data can be less then the input data if it is
      // not block aligned.
      short end = mSEProvider.encryptDecryptInPlace(buf, encDataStart, decryptedDataLen,
          mScratch, (short)0, (short) mScratch.length);
      // The response data starts at start with nonce.
      len = (short)(end - start);
      // now package the response as byte string - note this will add the header and decrement
      // the start pointer.
      start = addByteStringHeader(buf, start, len);
      len = (short)(end - start);
    }else if(op == FINISH){
      // Encrypts the remaining data, and it will also have auth tag appended at the end.
      // Encrypt
      short end = mSEProvider.encryptDecryptInPlace(buf, start, len,
          mScratch, (short)0, (short) mScratch.length);
      short finalLen = mSEProvider.doAesGcmOperation(buf,end,(short)0,mScratch, (short) 0, false);
      Util.arrayCopyNonAtomic(mScratch, (short) 0, buf, end, finalLen);
      end += finalLen;
      len = (short)(end - start);
      start = addByteStringHeader(buf, start, len);
      len = (short)(end - start);
    }else if(op == UPDATE){
      // Update operation encrypts the data and sends it back to client.
      // Encrypt
      short end = mSEProvider.encryptDecryptInPlace(buf, start, len,
          mScratch, (short)0, (short) mScratch.length);
      len = (short)(end - start);
      start = addByteStringHeader(buf, start, len);
      len = (short)(end - start);
    }else{
      ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
    }
    // now package the response as byte string - note this will add the header and decrement
    // the start pointer.
    sendApdu(apdu, start, len, true, (short) 0);
  }
  private short addByteStringHeader(byte[] buf, short start, short len){
    mEncoder.init(mScratch, (short)0, (short) 4);
    short offset = mEncoder.startByteString(len);
    start -= offset;
    Util.arrayCopyNonAtomic(mScratch, (short) 0, buf, start, offset);
    return start;
  }

  /**
   * This command can be used for starting, updating and finishing swap in. This is
   * indicated by the op parameter.
   */
  private void handleSwapInMdoc(APDU apdu, byte slot, byte op,
      short start, short len) {
    Mdoc doc = findDocument(slot);
    if (doc == null) {
      ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
    }
    byte[] buf = heap;//apdu.getBuffer();
    if(op == BEGIN){
      // Extract the nonce and then decrypt the data - then start storing it.
      // First 12 bytes will be nonce
      short encDataStart = (short)(start + SEProvider.AES_GCM_NONCE_LENGTH);
      short encDataLen = (short)(len - SEProvider.AES_GCM_NONCE_LENGTH);

      // Credential public key is the auth data - copy to scratch
      short credKeyLen = ((ECPublicKey)doc.getCredentialKey().getPublic()).getW(mScratch,
          (short)0);
      mSEProvider.beginAesGcmOperation(
          doc.getStorageKey(), false,
          buf, start, SEProvider.AES_GCM_NONCE_LENGTH,
          mScratch, (short)0, credKeyLen);
      doc.startProvisioning();

      // decrypt data - the decrypted data will be directly stored in the doc specific flash memory.
      short end = mSEProvider.encryptDecryptInPlace(
          buf, encDataStart,encDataLen,
          mScratch, (short)0, (short) mScratch.length);
      short size = (short)(end - encDataStart);
      doc.store(buf, encDataStart, size);
      // B
    }else if(op == FINISH){
      // Decrypts the remaining data, and it will store and then enumerate the data.
      short end = mSEProvider.encryptDecryptInPlace(
          buf, start,len, mScratch,(short) 0, (short)mScratch.length);
      short finalLen = mSEProvider.doAesGcmOperation(buf,end,(short)0,mScratch,(short) 0, false);
      Util.arrayCopyNonAtomic(mScratch, (short) 0, buf, end, finalLen);
      end += finalLen;
      short size = (short)(end - start);
      doc.store(buf, start, size);
      doc.commitProvisioning();
    }else if(op == UPDATE){
      // Update operation decrypts the data and stores it.
      short end = mSEProvider.encryptDecryptInPlace(
          buf, start,len, mScratch,(short) 0, (short)mScratch.length);
      short size = (short) (end - start);
      doc.store(buf, start, size);
    }else {
      ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
    }
  }


  /**
   * This command can be used for getting the information about the slot. If no slot is specified
   * then it returns hardware information. Else it returns usage information
   *
   */
  private void handleGetInformation(APDU apdu, byte slot) {
    //TODO change the hard coded INFORMATION
    if(slot < 0) {
      Util.arrayCopyNonAtomic(INFORMATION, (short) 0, apdu.getBuffer(), (short) 0,
          (short) INFORMATION.length);
      sendApdu(apdu, (short) 0, (short) INFORMATION.length, true, (short) 0);
    }else{
      Mdoc doc = findDocument(slot);
      if (doc == null) {
        ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
      }
      Util.setShort(apdu.getBuffer(), (short) 0, doc.getUsageCount());
      sendApdu(apdu, (short) 0, (short) 2, true, (short) 0);
    }
  }

  /**
   * This command may not be required.
   */
  private void handleSelectMdoc(byte slot){
    Mdoc doc = findDocument(slot);
    if (doc == null) {
      ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
    }
    if(mSelectedDocument[SELECT_MDOC] != null){
      reset();
    }
    mSelectedDocument[SELECT_MDOC] = doc;
    mContext[CTX_SELECTED_DOCUMENT] = SELECT_MDOC;
  }

  private void handleLookUpCredential(byte slot){
    Mdoc doc = findDocument(slot);
    if (doc == null || !doc.isReserved()) {
      ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
    }
  }
  private void handleDeleteCredential(byte slot){
    Mdoc doc = findDocument(slot);
    if (doc == null) {
      ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
    }
    destroyDocument(doc);
  }

  /**
   *   byte slot,byte testCred,
   *   short challenge_start, short challenge_len,
   *   short keyParams_start, short keyParams_len,
   *   short attest_keyParams_start, short attest_keyParams_len,
   *   short attest_keyBlob_start, short attest_keyBlob_len

   * }
   *
   */
  private void handleCreateMdocCred(APDU apdu, byte slot,boolean testCredential,
      short osVersionStart, short osVersionLen, short osPatchLevelStart, short osPatchLevelLen,
      short challengeStart, short challengeLen, short notBeforeStart, short notBeforeLen,
      short notAfterStart, short notAfterLen, short creationDateTimeStart,
      short creationDateTimeLen, short attAppIdStart, short attAppIdLen, short payLoadLen
  ){
    // Get the document
    Mdoc doc = findDocument(slot);
    if(doc == null || doc.isReserved()) {
      ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
    }
    // create the document
    createDocument(doc, MAX_MDOC_SIZE, testCredential,
        mScratch, (short)0, (short) mScratch.length);
    mContext[CTX_STATUS] = 0;
    byte[] buf = heap;//apdu.getBuffer();
    // Skip the input payload
    short start = (short) (/* ISO7816.OFFSET_EXT_CDATA */0 + payLoadLen);
    short certLen =
        mSEProvider.generateCredKeyCert((ECPublicKey) (doc.getCredentialKey().getPublic()),
    buf, osVersionStart, osVersionLen,
    buf, osPatchLevelStart,  osPatchLevelLen,
    buf, challengeStart, challengeLen,
    buf, notBeforeStart,  notBeforeLen,
    buf, notAfterStart,  notAfterLen,
    buf, creationDateTimeStart,  creationDateTimeLen,
    buf, attAppIdStart, attAppIdLen, testCredential,
    buf, start, MAX_BUFFER_SIZE,
    mScratch, (short)0, (short)mScratch.length);
    sendApdu(apdu, start, certLen,true,(short) 0);
  }

  private void handleCreateAuthKeys(APDU apdu, byte slot, short notBeforeStart, short notBeforeLen,
      short notAfterStart, short notAfterLen,
      short testDevAuthPublicKeyStart, short testDevAuthPublicKeyLen,
      short testDevAuthPrivateKeyStart, short testDevAuthPrivateKeyLen,
      short payloadLen){
    Mdoc doc = findDocument(slot);
    if (doc == null) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    //TODO remove the following line.
    // doc.enableTestCred(mScratch, (short)0, (short) mScratch.length);
    byte[] buf = heap; //apdu.getBuffer();
    // Generate the key pair
    mAuthKey.genKeyPair();
    //if the doc is test credential then client can provide test auth keys
    if (doc.isTestCredential()) {
      if (testDevAuthPrivateKeyLen > 0) {
        ((ECPrivateKey) mAuthKey.getPrivate()).setS(
            buf, testDevAuthPrivateKeyStart, testDevAuthPrivateKeyLen);
      }
      if (testDevAuthPublicKeyLen > 0) {
        ((ECPublicKey) mAuthKey.getPublic()).setW(
            buf, testDevAuthPublicKeyStart, testDevAuthPublicKeyLen);
      }
    }
    // Skip the input payload
    short start = payloadLen; //(short) (ISO7816.OFFSET_EXT_CDATA + payloadLen);
    mEncoder.init(buf, start, (short) (MAX_BUFFER_SIZE - payloadLen));
    mEncoder.startMap((short) 2);

    // Add the Certificate
    mEncoder.encodeUInt8(MdlSpecifications.KEY_CERT);
    // Generate and add cert - cert should not exceed 512 bytes.
    short certStart = (short) (MAX_BUFFER_SIZE - SEProvider.SIGNING_CERT_MAX_SIZE);
    short certLen =
        mSEProvider.generateSigningKeyCert((ECPublicKey)(mAuthKey.getPublic()),
            (ECPrivateKey) (doc.getCredentialKey().getPrivate()),
            buf, notBeforeStart,notBeforeLen,
            buf, notAfterStart, notAfterLen,
            buf,certStart,SEProvider.SIGNING_CERT_MAX_SIZE,
            mScratch,(short)0,(short)(mScratch.length));
    mEncoder.startByteString(certLen);
    Util.arrayCopyNonAtomic(buf, certStart, buf, mEncoder.getCurrentOffset(), certLen);
    mEncoder.increaseOffset(certLen);

    // Encrypt and add data.
    // Start the encrypt operation
    mSEProvider.generateRandomData(mScratch, (short)0, SEProvider.AES_GCM_NONCE_LENGTH);
    short size = ((ECPublicKey)doc.getCredentialKey().getPublic()).getW(mScratch,
        SEProvider.AES_GCM_NONCE_LENGTH);

    mSEProvider.beginAesGcmOperation(
        doc.getStorageKey(), true,
        mScratch, (short) 0, SEProvider.AES_GCM_NONCE_LENGTH,
        mScratch, SEProvider.AES_GCM_NONCE_LENGTH, size);

    // Encode the input data which is an array of 2 elements. We also add nonce in the front before
    // the array.
    mEncoder.encodeUInt8(MdlSpecifications.KEY_ENC_DATA);
    // len will be always 64 = 12 (nonce) + 32 (private key) + 16 (tag) + 1 (Array header) +
    // 2 (priv key bstr header) + 1 (encoded null)
    mEncoder.startByteString((short) 64);
   Util.arrayCopyNonAtomic(mScratch, (short)0, buf,  mEncoder.getCurrentOffset(),
       SEProvider.AES_GCM_NONCE_LENGTH);
    mEncoder.increaseOffset(SEProvider.AES_GCM_NONCE_LENGTH);
    short dataStart = mEncoder.getCurrentOffset();
    mEncoder.startArray((short)2);
    // first element is the private key as byte string
    size = ((ECPrivateKey)mAuthKey.getPrivate()).getS(mScratch, (short)0);
    mEncoder.encodeByteString(mScratch,(short)0, size);
    // second element is the credential data which is null at this stage so add cbor null type/value
    buf[mEncoder.getCurrentOffset()] = CBORBase.ENCODED_NULL;
    mEncoder.increaseOffset((short)1);
    short dataLen = (short) (mEncoder.getCurrentOffset() - dataStart);
    short i = (short) (mEncoder.getCurrentOffset() - start);
    // encrypt the data in place.
    short dataEnd = mSEProvider.encryptDecryptInPlace(buf, dataStart, dataLen,
        mScratch, (short)0, (short) mScratch.length);
    // Finish and add the auth tag
    short finalLen = mSEProvider.doAesGcmOperation(buf,dataEnd,(short)0,
        mScratch, (short) 0,  false);
    Util.arrayCopyNonAtomic(mScratch, (short) 0, buf, dataEnd, finalLen);
    dataEnd += finalLen;
    short len = (short)(dataEnd - dataStart + SEProvider.AES_GCM_NONCE_LENGTH);
    if(len != 64){ // this should never happen
      ISOException.throwIt(ISO7816.SW_UNKNOWN);
    }
    sendApdu(apdu, start, (short) (dataEnd - start), true, (short) 0);
  }

  private short sendNextChunk(APDU apdu){
    return ISO7816.SW_NO_ERROR;
  }


  private static void sendApdu(APDU apdu,  short start, short len,
      boolean lastChunk, short remainingLen) {
    short status = 0;
    if (!lastChunk) {
      if (remainingLen < (byte)0xFF) {
        status = (short) (ISO7816.SW_BYTES_REMAINING_00 | remainingLen);
      } else {
        status = ISO7816.SW_BYTES_REMAINING_00;
      }
    }
    apdu.setOutgoing();
    apdu.setOutgoingLength(len);
    //apdu.sendBytes(start, len);
    apdu.sendBytesLong(heap, start, len);
    if(status != 0) {
      ISOException.throwIt(status);
    }
  }
}
