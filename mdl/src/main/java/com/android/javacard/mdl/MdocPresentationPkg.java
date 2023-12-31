package com.android.javacard.mdl;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.ECPrivateKey;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;

public class MdocPresentationPkg {
  public final static short MAX_MDOC_SIZE = (short) 0x7FFF;
  public final static short MAX_DATA_ITEMS = (byte) 32;
  public final static short ELEM_KEY_ID_OFFSET = 0;
  public final static short ELEM_START_OFFSET = 1;
  public final static short ELEM_LENGTH_OFFSET = 2;
  public final static short ELEM_VALUE_START_OFFSET = 3;
  public final static short ELEM_VALUE_LENGTH_OFFSET = 4;
  public final static byte ELEM_TABLE_ROW_SIZE = 5;
  public final static short ELEM_TABLE_SIZE = (short) (MAX_DATA_ITEMS * ELEM_TABLE_ROW_SIZE);

  public final static byte NS_KEY_ID_OFFSET = 0;
  public final static byte NS_START_OFFSET = 1;
  public final static byte NS_END_OFFSET = 2;

  public final static byte MAX_NS_COUNT = 1;
  public final static byte NS_TABLE_ROW_SIZE = 3;
  public final static byte NS_TABLE_SIZE = (byte) (MAX_NS_COUNT * NS_TABLE_ROW_SIZE);
  public static final byte ITEM_KEY_OFFSET = 0;
  public static final byte ITEM_START = 1;
  public static final byte ITEM_LENGTH = 2;
  public static final byte ITEM_ROW_SIZE = 3;
  public static final byte MAX_ALLOWED_SIGNING_KEYS = 5;
  private static final short HEADER_SIZE = (short) 256;
  private static final short DATA_ENTRIES_INDEX = (short) 32;
  private short mUsageCount;
  private boolean mPreAllocatedMem;

  private KeyPair mAuthKey;

  // offsets and lengths of the data items in heap.
  private short mIssuerAuthStart;
  private short mIssuerAuthLength;
  private short mDigestMappingLength;
  private short mDigestMappingStart;
  private short mDocTypeStart;
  private short mDocTypeLen;
  private short mReaderAccessKeysStart;
  private short mReaderAccessKeysLen;
  private byte[] mHeap;
  private short mHeapIndex;
  private short mDataEnd;
  private short[] mNsTable;
  private byte mNsTableSize;
  private short[] mElementTable;
  private short mElementTableSize;
  private CBORDecoder mDecoder;
  private static short[] mTemp;

  /**
   * This class represents the presentation package which is the master document that gets
   * provisioned by the provisioning applet and presented by the presentation applet. This
   * document is persistently stored by provisioning applet and based on the usage counter it
   * gets swapped in and out. When reader queries about the data elements of the presentation
   * package then presentation applet generates a view of this document, which gets presented to
   * the reader.
   * In order to quickly create the presentation view, this class maintains several indexes such
   * as namespace table, elements table, etc.
   */
  public MdocPresentationPkg(){
    mDecoder = new CBORDecoder();
    mNsTable = new short[(short)(NS_TABLE_SIZE +1)];
    mElementTable = new short[(short) (ELEM_TABLE_SIZE + 1)];
    mAuthKey = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
    mAuthKey.genKeyPair();
    mTemp = new short[32];
  }

  public short getDataStart(){
    return 0;
  }

  public short getDataLength(){
    return mDataEnd;
  }

  public byte[] getBuffer(){
    return mHeap;
  }

  public void allocMem(short size){
    mHeap = new byte[size];
    mHeapIndex = 0;
  }
  public void freeMem(){
    if(mPreAllocatedMem){
      return;
    }
    mHeap = null;
    JCSystem.requestObjectDeletion();
  }

  public void resetUsageCount(){
    mUsageCount = 0;
  }

  public short getUsageCount(){
    return mUsageCount;
  }

  public KeyPair getAuthKeyPair(){
    return mAuthKey;
  }
  public short findNsEntry(short id){
    for(byte i = 0; i < mNsTableSize; i+=NS_TABLE_ROW_SIZE){
      if(mNsTable[i + NS_KEY_ID_OFFSET] == id){
        return i;
      }
    }
    return -1;
  }

  public short findElementEntry(short nsIndex, short elemId){
    short elemStart = (short) (mNsTable[nsIndex + NS_START_OFFSET]);
    short elemEnd =
        (short) (elemStart + mNsTable[nsIndex + NS_END_OFFSET]);
    for(short i = elemStart; i < elemEnd; i+=ELEM_TABLE_ROW_SIZE){
      if(mElementTable[i + ELEM_KEY_ID_OFFSET] == elemId){
        return i;
      }
    }
    return -1;
  }

  public short readElementRecord(short[] retArr, short start, short elemIndex){
    retArr[(short)(start +ELEM_KEY_ID_OFFSET)] =
        mElementTable[(short)(elemIndex +ELEM_KEY_ID_OFFSET)];
    retArr[(short)(start +ELEM_START_OFFSET)] =
        mElementTable[(short)(elemIndex +ELEM_START_OFFSET)];
    retArr[(short)(start +ELEM_LENGTH_OFFSET)] =
        mElementTable[(short)(elemIndex +ELEM_LENGTH_OFFSET)];
    retArr[(short)(start +ELEM_VALUE_START_OFFSET)] =
        mElementTable[(short)(elemIndex +ELEM_VALUE_START_OFFSET)];
    retArr[(short)(start +ELEM_VALUE_LENGTH_OFFSET)] =
        mElementTable[(short)(elemIndex +ELEM_VALUE_LENGTH_OFFSET)];
    return ELEM_TABLE_ROW_SIZE;
  }
  public void write(byte[] buf, short start, short len){
    if((short)(mHeapIndex + len) > (short) (mHeap.length)){
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
    Util.arrayCopyNonAtomic(buf, start, mHeap, mHeapIndex, len);
    mHeapIndex += len;
  }
  public short read(byte[] buf, short start, short len, short ns, short elem,
      short elemDataPtr){
    ns = (short) (ns * NS_TABLE_ROW_SIZE);
    if (ns >= mNsTableSize) {
      return 0;
    }
    elem = (short) (elem * ELEM_TABLE_ROW_SIZE);
    if (elem >= mElementTableSize) {
      return 0;
    }
    short remainingBytes = (short) (mElementTable[elem + ELEM_START_OFFSET] +
        mElementTable[elem + ELEM_LENGTH_OFFSET] - elemDataPtr);
    if (remainingBytes > len) {
      remainingBytes = len;
    }
    Util.arrayCopyNonAtomic(mHeap, elemDataPtr, buf, start, remainingBytes);
    return remainingBytes;
  }

  /**
   *      KEY_DOC_TYPE, CBOR_TEXT_STR,
   *       KEY_DIGEST_MAPPING, CBOR_MAP,
   *       KEY_ISSUER_AUTH, CBOR_ARRAY,
   *       KEY_READER_ACCESS, CBOR_MAP,
   *
   * First parse the cred data and extract digest mapping. Then parse the digest mapping and
   * extract the name space keys. Then for each namespace parse the array of the items. Finally
   * store each item in the element index table.
   */
  public void enumerate(short[] temp){
    // Parse the auth keys and cred data
    mDecoder.initialize(mHeap, getDataStart(), getDataLength());
    short size = mDecoder.readMajorType(CBORBase.TYPE_ARRAY);
    if(size != 2){
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
    size = mDecoder.readMajorType(CBORBase.TYPE_BYTE_STRING);
    if(size != (short) (KeyBuilder.LENGTH_EC_FP_256 / 8)){
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }

    ((ECPrivateKey)mAuthKey.getPrivate()).setS(mHeap, mDecoder.getCurrentOffset(), size);
    mDecoder.increaseOffset(size);
    // Now Parse the cred data.
    size = mDecoder.readMajorType(CBORBase.TYPE_BYTE_STRING);
    short[] struct =
        MdlSpecifications.getStructure(MdlSpecifications.KEY_CRED_DATA);
    MdlSpecifications.decodeStructure(struct, temp, mHeap, mDecoder.getCurrentOffset(), size);
    // Doc types should match
    if(!MdlSpecifications.compareDocTypes(MdlSpecifications.KEY_MDL_DOC_TYPE,mHeap, temp[0],
        temp[1])){
      delete();
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }

    mDocTypeStart = temp[0];
    mDocTypeLen = temp[1];
    mDigestMappingStart = temp[2];
    mDigestMappingLength = temp[3];
    mIssuerAuthStart = temp[4];
    mIssuerAuthLength = temp[5];
    mReaderAccessKeysStart = temp[6];
    mReaderAccessKeysLen = temp[7];

    // Parse the digest mapping
    struct =
        MdlSpecifications.getStructure(MdlSpecifications.IND_CRED_DATA_DIGEST_MAPPING);
    MdlSpecifications.decodeStructure(struct, temp, mHeap, mDigestMappingStart, mDigestMappingLength);
    // For each name space found in the digest mapping
    for(byte i = 0; i < (short)(struct.length) ; i += MdlSpecifications.STRUCT_ROW_SIZE){
      // Check if there is name space found
      if(temp[i] == 0){
        continue;
      }
      // Is this namespace already present in the ns table
      short nsKey = MdlSpecifications.NAMESPACES[(short)(i/MdlSpecifications.STRUCT_ROW_SIZE)];
      if(findNsEntry(nsKey) != -1){
        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
      }
      // Store the namespace in nsTable
      mNsTable[mNsTableSize++] = nsKey;
      mNsTable[mNsTableSize++] = temp[i];
      mNsTable[mNsTableSize++] = temp[(short)(i + 1)];
    }

    // Now for every entry in Ns Table enumerate the elements
    struct = MdlSpecifications.getStructure(MdlSpecifications.IND_ISSUER_SIGNED_ITEM);
    for(byte i = 0; i < mNsTableSize; i += NS_TABLE_ROW_SIZE) {
      short[] nsStruct = MdlSpecifications.getNsStructure(mNsTable[i]);
      short nsStart = mNsTable[(short) (i + 1)];
      short nsLen = mNsTable[(short) (i + 2)];
      mNsTable[(short) (i + 1)] = mElementTableSize;
      mDecoder.init(mHeap, nsStart, nsLen);
      short items = mDecoder.readMajorType(CBORBase.TYPE_ARRAY);
      while (items > 0) {
        short start = mDecoder.getCurrentOffset(); // semantic tag
        short end = mDecoder.skipEntry();

        MdlSpecifications.decodeTaggedStructure(struct, temp, mHeap, start, (short)(end - start));
        if (temp[1] == 0 || temp[3] == 0 || temp[5] == 0 || temp[7] == 0) {
          ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        short elemKey = MdlSpecifications.getNsElemKey(mNsTable[i], nsStruct, mHeap, temp[4]);
        if (elemKey == -1) {
          ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        mElementTable[mElementTableSize++] = elemKey;
        mElementTable[mElementTableSize++] = start;
        mElementTable[mElementTableSize++] =  (short) (end -start);
        mElementTable[mElementTableSize++] = temp[6];
        mElementTable[mElementTableSize++] = temp[7];
        items--;
      }
      // We store one more then actual end offset because we start from 0'th index.
      mNsTable[(short) (i + 2)] = mElementTableSize;
    }
  }

  public short getIssuerAuthStart(){
    return mIssuerAuthStart;
  }
  public short getIssuerAuthLength(){
    return mIssuerAuthLength;
  }

  public void create(short size){
    allocMem(size);
  }
  public void delete() {
    mHeapIndex = 0;
    mDigestMappingStart = mDocTypeStart = mIssuerAuthStart =
        mReaderAccessKeysStart = mReaderAccessKeysLen = mDigestMappingLength =
            mIssuerAuthLength = mDocTypeLen = -1;
    mElementTableSize = mNsTableSize = 0;
    freeMem();
  }
  public void setPreAllocated() {
    mPreAllocatedMem = true;
  }

  public void startProvisioning() {
    mHeapIndex = 0;
    mDataEnd = 0;
  }

  public void commitProvisioning() {
    mDataEnd = mHeapIndex;
    enumerate(mTemp);
  }

  public boolean isMatching(byte[] buf, short start, short len) {
    return len == mDocTypeLen &&
        Util.arrayCompare(buf, start, mHeap,mDocTypeStart, mDocTypeLen) == 0;
  }
  public boolean isReaderAuthRequired(){
    return mReaderAccessKeysStart >= 0;
  }
  public short getDocType(byte[] buf, short start){
    Util.arrayCopyNonAtomic(mHeap, mDocTypeStart, buf, start, mDocTypeLen);
    return mDocTypeLen;
  }
  public short[] getNameSpaces(){
    return mNsTable;
  }
}
