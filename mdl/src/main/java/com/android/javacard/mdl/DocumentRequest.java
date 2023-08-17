package com.android.javacard.mdl;

import com.android.javacard.mdl.jcardsim.SEProvider;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.ECPrivateKey;
import javacard.security.HMACKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.Signature;

public class DocumentRequest {
    // Element Entry consists of {element_key_id, element_value offset in the
    // document, element_val_len in the document}.
    // Namespace Entry consists of {Name Space Id amd offset in Element Entry Array}
    private static  final short ELEM_ARR_ENTRY_SIZE = 3;
    private static  final short NS_ARR_ENTRY_SIZE = 2;
    // Max 32 elements per namespace
    private static final short MAX_ELEMENTS_SIZE = (short) (ELEM_ARR_ENTRY_SIZE * 32);
    // Max 3 namespace per document request/
    private static final short MAX_NAMESPACES_SIZE = (short) (NS_ARR_ENTRY_SIZE * 3);;
    private static final short ELEM_ARRAY_LEN = MAX_ELEMENTS_SIZE;
    private static final byte ELEM_KEY = 0;
    private static final byte ELEM_START = 1;
    private static final byte ELEM_LEN = 2;
    private static final byte DOCUMENT = 0;
    private static final byte ELEMENTS = 1;
    private static final byte SESSION_DATA = 2;
    // Partial deviceSigned entry. The only thing not included here is the signature.
    private static final byte[] DEVICE_SIGNED ={
        // "deviceSigned"
        (byte)(MdlSpecifications.CBOR_TEXT_STR | (short)12),
        0x64, 0x65, 0x76, 0x69, 0x63, 0x65, 0x53, 0x69, 0x67, 0x6e, 0x65, 0x64,
        // Map of 2 elements
        (byte)(MdlSpecifications.CBOR_MAP | (short)2),
        // First element will always be empty namespaces because currently we do not support items
        // specific device authentication
        // "nameSpaces"
        (byte)(MdlSpecifications.CBOR_TEXT_STR | (short)10),
        0x6e, 0x61, 0x6d, 0x65, 0x53, 0x70, 0x61, 0x63, 0x65, 0x73,
        // Semantic tag with binary string containing map of zero element. This is same as
        // DEVICE_NAMESPACES which is used to generate the mac in the CoseMac0 structure.
        (byte)(MdlSpecifications.CBOR_SEMANTIC_TAG | MdlSpecifications.CBOR_UINT8_LENGTH),
        (byte)MdlSpecifications.CBOR_SEMANTIC_TAG_ENCODED_CBOR,
        (byte)(MdlSpecifications.CBOR_BINARY_STR | (short)1),
        (byte)(MdlSpecifications.CBOR_MAP),
        // Second element will be deviceAuth.
        (byte)(MdlSpecifications.CBOR_TEXT_STR | (short)10),
        0x64, 0x65, 0x76, 0x69, 0x63, 0x65, 0x41, 0x75, 0x74, 0x68,
        // Device auth value is a map of one element which is CoseMac0 structure
        // Map of 1 element
        (byte)(MdlSpecifications.CBOR_MAP | (byte)1),
        // Element: key is "deviceMac" text string
        (byte)(MdlSpecifications.CBOR_TEXT_STR | (byte)9),
        0x64, 0x65, 0x76, 0x69, 0x63, 0x65, 0x4d, 0x61, 0x63,
        // Element: value is an array i.e. CoseMac0 structure
        // Array of 4 elements
        (byte)(MdlSpecifications.CBOR_ARRAY | (byte) 0x04),
        // First element: byte string of protected Header containing a map: Alg (1) = HMAC 256 (5)
        (byte)(MdlSpecifications.CBOR_BINARY_STR | (byte)0x03),
        // protected header is map of 1 element
        (byte)(MdlSpecifications.CBOR_MAP | (byte) 0x01),
        // Alg key is Uint 1 and value is 5
        (byte)(MdlSpecifications.CBOR_UINT | (byte)0x01),
        (byte)(MdlSpecifications.CBOR_UINT | (byte)5),
        // Second element: unsupported header i.e. cbor map of zero length.
        (byte)(MdlSpecifications.CBOR_MAP),
        // Third Element: Payload which is nil i.e. simple value 0xf6.
        (byte)0xF6,
        // Fourth Element: Binary String Mac (32 bytes)
        (byte)(MdlSpecifications.CBOR_BINARY_STR | MdlSpecifications.CBOR_UINT8_LENGTH),
        (byte)32,
        // Add the mac after this.
    };
    // Zero sized Device Name spaces.
    // TODO in future this can change i.e. document can have different name spaces. So the code
    //  needs to change to support that.
    private static final byte[] DEVICE_NAMESPACES = {
        (byte)(MdlSpecifications.CBOR_SEMANTIC_TAG | MdlSpecifications.CBOR_UINT8_LENGTH),
        (byte)MdlSpecifications.CBOR_SEMANTIC_TAG_ENCODED_CBOR,
        (byte)(MdlSpecifications.CBOR_BINARY_STR | (short)1),
        (byte)(MdlSpecifications.CBOR_MAP),
    };
    private static final byte[] MAC0_STRUCT = {(byte)0x84, // Array of 4 elements
        0x64, 0x4D, 0x41, 0x43, 0x30, // text string of "MAC0"
        0x43, (byte)0xA1, 0x01, 0x05, // protected
        0x40, // external aad empty byte string
        // payload which will be a byte string
    };
    private Object[] mPresentationPkg;
    private short[] mElements;
    private boolean[] error;
    private short[] errorCode;
    private Object[] mRequest;
    private short[] mNsTable;
    private short mNsTableEnd;
    private short[] mElementTable;
    private short mElementTableEnd;
    private byte[] mMacTag;
    private CBORDecoder mDecoder;
    private  CBOREncoder mEncoder;
    private HMACKey mDeviceAuthKey;
    private Signature mDeviceAuth;
    static KeyAgreement mKeyAgreement;
    private CBOREncoderCalc mCalc;

    public DocumentRequest(){
        mPresentationPkg = JCSystem.makeTransientObjectArray((short)1,
            JCSystem.CLEAR_ON_DESELECT);
        // Create element array with length one more than MAX ELEMENTS as the last entry will be
        // length of the
        // element array.
        mElements = JCSystem.makeTransientShortArray((short) (MAX_ELEMENTS_SIZE +1), JCSystem.CLEAR_ON_DESELECT);
        error = JCSystem.makeTransientBooleanArray((short) 1, JCSystem.CLEAR_ON_DESELECT);
        errorCode = JCSystem.makeTransientShortArray((short) 1, JCSystem.CLEAR_ON_DESELECT);
        mRequest = JCSystem.makeTransientObjectArray((short) 1, JCSystem.CLEAR_ON_DESELECT);
        mNsTable = JCSystem.makeTransientShortArray(MdocPresentationPkg.NS_TABLE_SIZE, JCSystem.CLEAR_ON_DESELECT);
        mElementTable =
            JCSystem.makeTransientShortArray(MdocPresentationPkg.ELEM_TABLE_SIZE, JCSystem.CLEAR_ON_DESELECT);
        // 32 bytes of tag + two bytes of CBOR bStr header (short encoding).
        mMacTag = JCSystem.makeTransientByteArray((short)(MdlSpecifications.CBOR_MAC_TAG_SIZE+2),
            JCSystem.CLEAR_ON_DESELECT);
        mDecoder = new CBORDecoder();
        mEncoder = new CBOREncoder();
        mCalc = new CBOREncoderCalc();
        mDeviceAuthKey = (HMACKey) KeyBuilder.buildKey(KeyBuilder.TYPE_HMAC,
            KeyBuilder.LENGTH_HMAC_SHA_256_BLOCK_64, false);
        mDeviceAuth = Signature.getInstance(Signature.ALG_HMAC_SHA_256, false);
        mKeyAgreement = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN, false);
    }
    public void reset(){
        mPresentationPkg[0] = null;
        mElements[MAX_ELEMENTS_SIZE] = 0;
        error[0] = false;
        errorCode[0] = 0;
        mRequest = null;
    }
    public byte[] getDeviceAuthMacTag(){
        return mMacTag;
    }
    public void setDocument(MdocPresentationPkg doc){
       mPresentationPkg[0] = doc;
    }
    public MdocPresentationPkg getDocument(){
        return (MdocPresentationPkg) mPresentationPkg[0];
    }
    public void setError(){
        error[0] = true;
    }
    public boolean isError(){
        return error[0];
    }
    public void setErrorCode(short err){
        errorCode[0] = err;
    }
    public short getErrorCode(){
        return errorCode[0];
    }

    public short getDocType(byte[] buf, short start){
        if(mPresentationPkg[0] != null) {
            return ((MdocPresentationPkg) mPresentationPkg[0]).getDocType(buf, start);
        }
        return -1;
    }
    public short[] getNsTable(){
        return mNsTable;
    }
    public short[] getElemTable(){
        return mElementTable;
    }
    public short getNsTableEnd(){
        return mNsTableEnd;
    }
    public short getElemTableEnd(){
        return mElementTableEnd;
    }
    boolean init(MdocPresentationPkg doc, short[] tmpArray,
        byte[] buf, short nameSpacesStart, short nameSpacesLen,
        byte[] scratch, short scratchStart, short scratchLen){
        reset();
        // init the decoder
        mDecoder.init(buf,nameSpacesStart,nameSpacesLen);
        if(mDecoder.getMajorType() != CBORBase.TYPE_MAP){
            return false;
        }
        // Read the top map which contains namespaces as keys and data items as value.
        short numElements = mDecoder.readMajorType(CBORBase.TYPE_MAP);

        // For each requested namespace
        for(short i = 0; i < numElements; i ++){
            // Resolve the key
            short nsKey = MdlSpecifications.getNameSpacesKey(buf, mDecoder.getCurrentOffset());
            if(nsKey < 0){
                return false;
            }
            // If the key is present in this document
            short nsEntryIndex = doc.findNsEntry(nsKey);
            if( nsEntryIndex < 0){
                return false;
            }
            mDecoder.skipEntry(); // skips the ns key in the request
            // Read the value i.e. map of data elements
            if(mDecoder.getMajorType() != CBORBase.TYPE_MAP){
                return false;
            }
            short dataElemCount = mDecoder.readMajorType(CBORBase.TYPE_MAP);
            short[] nsStruct = MdlSpecifications.getNsStructure(nsKey);

            // Save the namespace key
            mNsTable[(short)(mNsTableEnd +MdocPresentationPkg.NS_KEY_ID_OFFSET)] = nsKey;
            mNsTable[(short)(mNsTableEnd + MdocPresentationPkg.NS_START_OFFSET)] = mElementTableEnd;

            // For each data element requested in this namespace
            for(short j = 0; j < dataElemCount ; j++){
                // Resolve the data element key
                short elemKey = MdlSpecifications.getNsElemKey(nsKey, nsStruct, buf,
                    mDecoder.getCurrentOffset());
                short elemEntryIndex = -1;
                if(elemKey >= 0) {
                    // Now find the start and stop of the element from the doc.
                    elemEntryIndex = doc.findElementEntry(nsEntryIndex, elemKey);
                }
                if(elemKey < 0 || elemEntryIndex < 0){
                    mElementTable[mElementTableEnd + MdocPresentationPkg.ELEM_KEY_ID_OFFSET] =
                        elemKey;
                    mElementTable[mElementTableEnd + MdocPresentationPkg.ELEM_START_OFFSET] =
                        MdlSpecifications.MDL_ERR_NOT_FOUND;
                }else {
                    mElementTableEnd += doc.readElementRecord(mElementTable, mElementTableEnd,
                        elemEntryIndex);
                }
                mDecoder.skipEntry(); // skip the element identifier key
                mDecoder.skipEntry(); // skip the value - this is the intentToRetain
            }
            mNsTable[(short)(mNsTableEnd + MdocPresentationPkg.NS_END_OFFSET)] =
                (short) (mElementTableEnd -
                mNsTable[(short)(mNsTableEnd + MdocPresentationPkg.NS_START_OFFSET)]);
            mNsTableEnd += MdocPresentationPkg.NS_TABLE_ROW_SIZE;
        }
        setDocument(doc);
        // At this we can generate device authentication mac tag.
        try {
            return generateDeviceAuthMacTag(scratch, scratchStart, scratchLen);
        }catch (Exception e){
            return false;
        }
    }

    /**
     * This method digests Mac0 structure and generates the Mac Tag.
     * Mac0 Structure is partially defined MAC0_STRUCT - to which detached content is added as
     * payload.
     * Detached content is as follows:
     * DeviceAuthenticationBytes = #6.24(bstr .cbor DeviceAuthentication)
     * DeviceAuthentication = [
     *               "DeviceAuthentication",
     *               SessionTranscript,
     *               DocType, ; Same as in mdoc response
     *               DeviceNameSpacesBytes ; Same as in mdoc response
     *             ]
     * The Mac Tag generated by digesting the data is then appended to CoseMac0 structure defined
     * in COSE_MAC0_STRUCT during presentation.
     */
    public boolean generateDeviceAuthMacTag(
        byte[] scratchPad, short start, short len) {
        // Initializes mDeviceAuth - this is HMac Signer.
        initDeviceAuth(this, scratchPad, start, len);

        // Create Mac Structure to generate CoseMac0.
        // Digest the partial Mac0 structure
        mDeviceAuth.update(MAC0_STRUCT, (short) 0, (short) MAC0_STRUCT.length);

        // Now add detached content which is tagged binary string and hence we need to know the
        // length before we can encode and digest it.
        // Calculate the length.
        short transLen = Util.getShort(Session.mSessionTranscript, (short) 0);
        short documentNameSpaceLen =
            calculateDocumentNameSpaceLength(this, scratchPad, start, len);
        short deviceNameSpaceLen = calculateDeviceNameSpaceLength(documentNameSpaceLen);
        short docTypeLength = ((MdocPresentationPkg) mPresentationPkg[0]).getDocType(scratchPad, start);

        // total detached content len
        short detachedContentLen = (short) (
            //Cbor array with 4 elements (1)
            1 +
            // "DeviceAuthentication" text string
            (short) MdlSpecifications.deviceAuthentication.length +
            // Cbor Encoded Session Transcript length
            transLen +
            // doc type length
            (short) MdlSpecifications.mdlDocType.length +
            // Calculated device namespaces length
            deviceNameSpaceLen);
        // Now we can encode and digest the detached content
        mEncoder.init(scratchPad, start, len);
        if(detachedContentLen < CBORBase.ENCODED_ONE_BYTE){
            mEncoder.startByteString((short) (detachedContentLen + 3));// SemTag (2) + bStr(1)
        }else if(detachedContentLen < (short) 0x100){
            mEncoder.startByteString((short) (detachedContentLen + 4)); //// SemTag (2) + bStr(2)
        }else{
            mEncoder.startByteString((short) (detachedContentLen + 5)); //// SemTag (2) + bStr(3)
        }
        // Add Tagged DeviceAuthenticationBytes
        mEncoder.encodeTag((byte)MdlSpecifications.CBOR_SEMANTIC_TAG_ENCODED_CBOR);
        mEncoder.startByteString(detachedContentLen);
        // Add the Device Authentication array as part of DeviceAuthenticationBytes
        mEncoder.startArray((short)4);
        // Element 1: deviceAuthentication text string
        mEncoder.encodeRawData(MdlSpecifications.deviceAuthentication, (short) 0,
            (short)MdlSpecifications.deviceAuthentication.length);
        // Digest the partial encoded data at this point.
        mDeviceAuth.update(scratchPad, start, (short) (mEncoder.getCurrentOffset() - start));
        // Element 2: Session transcript
        mDeviceAuth.update(Session.mSessionTranscript, (short) 2, transLen);
        // Element 3: doc type
        ((MdocPresentationPkg) mPresentationPkg[0]).getDocType(scratchPad, start);
        // Digest the doc type at this point
        mDeviceAuth.update(scratchPad, start, docTypeLength);
        // Element 4: Encode and digest document name spaces.
        encodeAndDigestDocumentNamespaces(this,mDeviceAuth, scratchPad, start, len);
        // Now generate the mac tag
        mEncoder.init(mMacTag, (short)0, (short)mMacTag.length);
        mEncoder.startByteString( MdlSpecifications.CBOR_MAC_TAG_SIZE);
        if(mDeviceAuth.sign(scratchPad, start, (short)0, mMacTag, (short)2)
            != MdlSpecifications.CBOR_MAC_TAG_SIZE){
            return false;
        }
        System.out.println("Device Side - Device Auth Mac Tag:");
        SEProvider.print(mMacTag, (short)0, (short) mMacTag.length);
        return true;
    }
    void initDeviceAuth(DocumentRequest request, byte[] scratch, short start, short len){
        // Derive Device Secret for mdoc signing
        ECPrivateKey devicePrivKey = (ECPrivateKey)request.getDocument().getAuthKeyPair().getPrivate();
        mKeyAgreement.init(devicePrivKey);
//      pubLen = MdlDocument.getReaderPublicKey().getW(scratchPad, pubStart);
//      secretLen = mKeyAgreement.generateSecret(scratchPad, pubStart, pubLen, scratchPad,
//          secretStart);
        short pubLen = Session.mEReaderKeyPub.getW(scratch, start);
        short secretStart = (short) (start + pubLen);
        short secretLen = mKeyAgreement.generateSecret(scratch, start, pubLen, scratch,
            secretStart);
        short saltStart = (short) (secretStart + secretLen);
        short saltLen = (short) Session.mSalt.length;
        short outStart = Util.arrayCopyNonAtomic(Session.mSalt, (short) 0, scratch, saltStart,
            saltLen);
        short outLen = Session.hkdf(scratch, saltStart, saltLen, scratch, secretStart, secretLen,
            MdlSpecifications.eMacKey,scratch, outStart);
        System.out.println("Device Side Device EMacKey:");
        SEProvider.print(scratch, outStart, outLen);
        mDeviceAuthKey.setKey(scratch, outStart, outLen);
        mDeviceAuth.init(mDeviceAuthKey, Signature.ALG_HMAC_SHA_256);
    }

    short encodeAndDigestDocumentNamespaces(DocumentRequest request, Signature digest,
        byte[] scratch, short start, short len){
        short dataLen = 0;
        mEncoder.init(scratch, start, len);
        short[] nsTable = request.getNsTable();
        short nsTableSize = request.getNsCount();
        short[] elemTable = request.getElemTable();
        MdocPresentationPkg pkg = request.getDocument();
        mEncoder.startMap(nsTableSize);
        for(byte i = 0; i < nsTableSize; i+=MdocPresentationPkg.NS_TABLE_ROW_SIZE){
            short nsId = nsTable[(short)(i+MdocPresentationPkg.NS_KEY_ID_OFFSET)];
            byte[] nsStr = MdlSpecifications.getDocNameSpaceString(nsId);
            SEProvider.print(nsStr, (short)0, (short)nsStr.length);
            mEncoder.encodeRawData(nsStr,(short)0, (short) nsStr.length);
            short elemTableSize = request.getElementCountForNs(i);
            mEncoder.startMap(elemTableSize);
            digest.update(scratch, start, mEncoder.getCurrentOffset());
            dataLen += mEncoder.getCurrentOffset();
            for(byte j = 0; j < elemTableSize; j++){
                short offset = (short)(j* MdocPresentationPkg.ELEM_TABLE_ROW_SIZE);
                short elemId =
                    elemTable[(short)( offset+ MdocPresentationPkg.ELEM_KEY_ID_OFFSET)];
                byte[] elemIdStr = MdlSpecifications.getNameSpaceElements_Mdl(elemId);
                SEProvider.print(elemIdStr, (short)0, (short)elemIdStr.length);
                digest.update(elemIdStr, (short)0, (short) elemIdStr.length);
                digest.update(pkg.getBuffer(),
                        elemTable[(short)(offset + MdocPresentationPkg.ELEM_VALUE_START_OFFSET)],
                        elemTable[(short)(offset + MdocPresentationPkg.ELEM_VALUE_LENGTH_OFFSET)]);
                dataLen += (short)elemIdStr.length;
                dataLen += elemTable[(short)(offset + MdocPresentationPkg.ELEM_VALUE_LENGTH_OFFSET)];
            }
            mEncoder.init(scratch,start,len);
        }
        return dataLen;
    }
    void encodeAndDigestDeviceNamespace(DocumentRequest request, short dataLen,
        Signature digest, byte[] scratch, short start, short len){
        //Reserve 5 bytes in the beginning as we have to add Semantic tag and byte string headers
        // in the end.
        mEncoder.init(scratch, start, len);
        // add sem tag
        mEncoder.encodeTag((byte)MdlSpecifications.CBOR_SEMANTIC_TAG_ENCODED_CBOR);
        //add byte string header + length (0, 1 or 2 bytes).
        mEncoder.startByteString(dataLen);
        digest.update(scratch, start, len);
        short nsLen = encodeAndDigestDocumentNamespaces(request, digest, scratch, start, len);
        if(nsLen != dataLen){
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }
    }
    short getNsCount(){
        return (short) (getNsTableEnd()/ MdocPresentationPkg.NS_TABLE_ROW_SIZE);
    }
    short getElementCountForNs(short nsIndex){
        nsIndex = (short) (nsIndex * MdocPresentationPkg.NS_TABLE_ROW_SIZE);
        short start = mNsTable[(short)(nsIndex + MdocPresentationPkg.NS_START_OFFSET)];
        short end  = mNsTable[(short)(nsIndex + MdocPresentationPkg.NS_END_OFFSET)];
        return (short) ((end - start) / MdocPresentationPkg.ELEM_TABLE_ROW_SIZE);
    }

    short calculateDocumentNameSpaceLength(DocumentRequest request,
        byte[] scratch, short start, short len){
        short dataLen = 0;
        mCalc.initialize((short)0, (short)5000);
        short[] nsTable = request.getNsTable();
        short nsTableSize = request.getNsCount();
        short[] elemTable = request.getElemTable();
        mCalc.startMap(nsTableSize);
        for(byte i = 0; i < nsTableSize; i+=MdocPresentationPkg.NS_TABLE_ROW_SIZE){
            short nsId = nsTable[(short)(i+MdocPresentationPkg.NS_KEY_ID_OFFSET)];
            byte[] nsStr = MdlSpecifications.getDocNameSpaceString(nsId);
            SEProvider.print(nsStr, (short)0, (short)nsStr.length);
            mCalc.encodeRawData(nsStr,(short)0, (short) nsStr.length);
            short elemTableSize = request.getElementCountForNs(i);
            mCalc.startMap(elemTableSize);
            for(byte j = 0; j < elemTableSize; j++){
                short offset = (short)(j* MdocPresentationPkg.ELEM_TABLE_ROW_SIZE);
                short elemId =
                    elemTable[(short)( offset+ MdocPresentationPkg.ELEM_KEY_ID_OFFSET)];
                byte[] elemIdStr = MdlSpecifications.getNameSpaceElements_Mdl(elemId);
                SEProvider.print(elemIdStr, (short)0, (short)elemIdStr.length);
                mCalc.encodeRawData(elemIdStr,(short)0, (short) elemIdStr.length);
                dataLen += elemTable[(short)(offset + MdocPresentationPkg.ELEM_VALUE_LENGTH_OFFSET)];
            }
        }
        dataLen += mCalc.getCurrentOffset();
        return dataLen;
    }
    static short calculateDeviceNameSpaceLength(short dataLen){
        // Adjust the final data length according to wrapped documentNameSpace lengths
        if(dataLen > 0x100){
            dataLen += 5;
        }else if(dataLen >= CBORBase.ENCODED_ONE_BYTE && dataLen < 0x100){
            dataLen += 4;
        }
        return dataLen;
    }

    public short getElementStart(short nsIndex, short elemIndex) {
        nsIndex = (short)(nsIndex * MdocPresentationPkg.NS_TABLE_ROW_SIZE);
        short elemTableStart = mNsTable[nsIndex + MdocPresentationPkg.NS_START_OFFSET];
        elemIndex = (short)((elemIndex * MdocPresentationPkg.ELEM_TABLE_ROW_SIZE) + elemTableStart);
        return mElementTable[(elemIndex +  MdocPresentationPkg.ELEM_START_OFFSET)];
    }

    public short getElementLen(short nsIndex, short elemIndex) {
        nsIndex = (short)(nsIndex * MdocPresentationPkg.NS_TABLE_ROW_SIZE);
        short elemTableStart = mNsTable[nsIndex + MdocPresentationPkg.NS_START_OFFSET];
        elemIndex = (short)((elemIndex * MdocPresentationPkg.ELEM_TABLE_ROW_SIZE) + elemTableStart);
        return mElementTable[(elemIndex +  MdocPresentationPkg.ELEM_LENGTH_OFFSET)];
    }

    public byte[] getNsId(short nsIndex) {
        nsIndex = (short)(nsIndex * MdocPresentationPkg.NS_TABLE_ROW_SIZE);
        short nsId = mNsTable[nsIndex + MdocPresentationPkg.NS_KEY_ID_OFFSET];
        return MdlSpecifications.getDocNameSpaceString(nsId);
    }

    /*
    // decode one namespace in an document_request->namespaces.
    static short decodeNameSpaceInDocumentRequest(short nsId, short[] retStructure, byte[] buffer,
                                                  short index,
                                                  short length){
        clearStructure(retStructure);
        CBORDecoder decoder = MdlUtil.decode(buffer, index, length);
        short numElements = decoder.readMajorType(CBORBase.TYPE_MAP);
        for(short i = 0; i < numElements){
            short rowIndex = getKey(reqType, decoder.getBuffer(), decoder.getCurrentOffset()); // returns matching row in structure
            // All keys are used only once in a device request.
            // TODO in the future this can be extended such that cardinality is part of the rule
            if(retStructure[rowIndex] != 0){
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }
            short valType = reqType[(short)(rowIndex + MdlSpecifications.STRUCT_VAL_OFFSET)];
            short valStart = decoder.skipEntry(); // skip the key part
            assertValType(valType, buffer, valStart);
            if(retStructure[rowIndex] != 0){
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }
            short valEnd = decoder.skipEntry(); // skip the value
            short valLen = (short) ( valEnd - valStart);
            retStructure[rowIndex++] = valStart;
            retStructure[rowIndex] = valLen;
            SEProvider.print(buffer, valStart, valLen);
            numElements--;
        }
        return decoder.getCurrentOffset();
    }
*/

}
