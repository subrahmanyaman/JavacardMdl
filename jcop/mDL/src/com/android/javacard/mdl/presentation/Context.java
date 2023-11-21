package com.android.javacard.mdl.presentation;

import javacard.framework.JCSystem;
import javacard.framework.Util;

/**
 * This class stores the information in current context of the presentation applet.
 * This information is related to the device request and response process.
 */
public class Context {
  //Incremental Response states
  public final static byte RESP_IDLE = 0;
  public final static byte RESP_START = 1;
  public final static byte RESP_DOCUMENT = 2;
  public final static byte RESP_DEVICE_SIGNED = 3; // We do not divide this in individual parts.
  public final static byte RESP_ISSUER_SIGNED = 4;
  public final static byte RESP_ISSUER_AUTH = 5;
  public final static byte RESP_ISSUER_NS = 6;
  public final static byte RESP_NS_ELEMENTS = 7;
  public final static byte RESP_NS_ELEMENT = 8;
  public final static byte CURRENT_DOC = 0;
  public final static byte CURRENT_STATE = 1;
  public final static byte CURRENT_NAMESPACE = 2;
  public static final byte CURRENT_ELEMENT = 3;
  public static final byte CURRENT_DATA_PTR_START = 4;
  public static final byte CURRENT_DATA_PTR_END = 5;
  static final byte MAX_DOC_REQUESTS = 2;
  // Buffer related metadata
  public static final short MAX_BUF_SIZE = 5096;
  public short[] mIncrementalResponseState;
  Object[] mDocumentRequests;
  // Stores the request message from the reader and response message to reader. The size is equal
  // to MAX_BUFFER_SIZE.
  byte[] mBuffer;
  // start of the data to be read.
  short[] mBufReadIndex;
  // cursor for the data to be written.
  short[] mBufWriteIndex;
  // Maximum size of the data expected by the reader. This has to be less than MAX_BUFFER_SIZE by
  // at least 256 bytes, in order to allow us to handle non aligned key value pairs and also auth
  // tag.
  short[] mChunkSize;
  // Total remaining encoded data from the package. When device request is received the
  // presentation applet calculates this value based on available data in the presentation
  // packaged provisioned earlier. This value is decremented everytime some data from presentation
  // package is encoded and encrypted and copied in to context buffer.
  short[] mRemainingBytes;
  // Total number of documents that has to be sent in the response to the reader.
  byte[] mDocumentsCount;
  // List of the instances of processed DocumentRequest which are to be returned back to the reader.
  Object[] mDocuments;

  // This method initializes the static data structures. It is executed during installation time.
  void init(byte[] buffer){
    mBuffer = buffer; //JCSystem.makeTransientByteArray(MAX_BUF_SIZE,JCSystem.CLEAR_ON_DESELECT);
    mBufReadIndex = JCSystem.makeTransientShortArray((short)1,JCSystem.CLEAR_ON_DESELECT);
    mBufWriteIndex = JCSystem.makeTransientShortArray((short)1, JCSystem.CLEAR_ON_DESELECT);
    mRemainingBytes = JCSystem.makeTransientShortArray((short)1, JCSystem.CLEAR_ON_DESELECT);
    mDocumentsCount = JCSystem.makeTransientByteArray((short)1, JCSystem.CLEAR_ON_DESELECT);
    mDocumentRequests =  JCSystem.makeTransientObjectArray(MAX_DOC_REQUESTS,JCSystem.CLEAR_ON_RESET);

    mChunkSize = JCSystem.makeTransientShortArray((short)1, JCSystem.CLEAR_ON_DESELECT);
    mDocuments =  JCSystem.makeTransientObjectArray((short)1, JCSystem.CLEAR_ON_RESET);

    for(byte i = 0; i < MAX_DOC_REQUESTS; i++){
      // Each Device request will have pointer to reader auth, DocType i.e. mdl or another doc
      // type and itemsRequests bytes used for reader auth. The pointer will have two fields i.e.
      // length and start in the mBuffer Note we are currently only supported doc type processing
      // and reader auth processing. In the future we may support the individual element processing.
      mDocumentRequests[i] = new DocumentRequest();
      // Each device response corresponds to associated requested doc type. It will have
      // two pointers - one pointer is index in doc table and another pointer is the index in MSO
      // table.
    }
    mIncrementalResponseState = JCSystem.makeTransientShortArray((short)7,
        JCSystem.CLEAR_ON_DESELECT);
  }
  void reset(){
    clearBuffer();
    mChunkSize[0] = 0;
    mRemainingBytes[0] = 0;
    mBufWriteIndex[0] = 0;
    mIncrementalResponseState[0] = RESP_IDLE;
    mIncrementalResponseState[1] = 0;
    clearDocumentRequests();
  }
  void clearBuffer(){
    Util.arrayFillNonAtomic(mBuffer,(short)0, (short)mBuffer.length, (byte)0);
  }
  void clearDocumentRequests(){
    for(byte i = 0; i < MAX_DOC_REQUESTS; i++){
      ((DocumentRequest)mDocumentRequests[i]).reset();
    }
    mDocumentsCount[0] = 0;
  }
  void setOutGoing(short chunkSize, short responseSize, short currentDoc){
    mRemainingBytes[0] = responseSize;
    // Actual chunk size is always two bytes less because the two bytes are always consumed by
    // status word.
    mChunkSize[0] = (short) (chunkSize - 2);
    mBufReadIndex[0] = 0;
    mBufWriteIndex[0] = 0;
    mIncrementalResponseState[Context.CURRENT_STATE] = RESP_START;
    mIncrementalResponseState[Context.CURRENT_NAMESPACE] = 0;
    mIncrementalResponseState[Context.CURRENT_ELEMENT] = 0;
    mIncrementalResponseState[Context.CURRENT_DATA_PTR_START] = 0;
    mIncrementalResponseState[Context.CURRENT_DATA_PTR_END] = 0;
    // Select the first document and then send that.
    mIncrementalResponseState[Context.CURRENT_DOC] = currentDoc;
  }
}
