package com.android.javacard.mdl.presentation;

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
    private static final byte[] SIGN1_Signature1 ={
        0x6A, 0x53, 0x69, 0x67, 0x6E, 0x61, 0x74, 0x75, 0x72, 0x65, 0x31
    };
    // alg = -7
    private static final byte[] SIGN1_ALG_ES256 = {(byte)0xA1, 0x01, 0x26};
    // alg = -35
    private static final byte[] SIGN1_ALG_ES384 = {(byte)0xA1, 0x01, 0x38, (byte)34};

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

    /**
     * Generate thee sig structure and then verify the signature.
     * detached content is as follows:
     * ReaderAuthenticationBytes = #6.24(bstr .cbor ReaderAuthentication)
     * ReaderAuthentication = [
     * "ReaderAuthentication",
     * SessionTranscript,
     * ItemsRequestBytes ;
     * ]
     */
    private boolean performReaderAuth(
        byte[] buf, short itemsBytesStart, short itemsBytesLen,
        byte[] sessionTrans, short sessionTransStart, short sessionTransLen,
        short alg,
        byte[] pub, short pubKeyStart, short pubKeyLen,
        byte[] sign, short signStart, short signLen,
        byte[] scratch, short scratchStart, short scratchLen) {

        // Convert the sign to ASN1 format
        short len = X509CertHandler.convertCoseSign1SignatureToAsn1(sign, signStart, signLen,
            scratch, scratchStart, (short)(scratchLen - signLen));
        if(len < 0){
            return false;
        }
        signLen = len;
        scratchLen -= signLen;
        signStart = scratchStart;
        scratchStart = (short) (signStart + signLen);
        sign= scratch;

        // Get the verifier
        Signature verifier = SEProvider.instance().getVerifier(pub, pubKeyStart, pubKeyLen, alg,
            Signature.MODE_VERIFY);
        if(verifier == null) return false;

        // Calculate the payload len
        short readerAuthLen = (short)(1 + // array header
            MdlSpecifications.readerAuthentication.length + // "ReaderAuthentication"
            sessionTransLen + //SessionTranscript
            itemsBytesLen);//ItemsRequestBytes
        // And calculate the cbor tagged byte string length
        mEncoder.init(scratch, scratchStart, scratchLen);
        mEncoder.encodeTag((byte)MdlSpecifications.CBOR_SEMANTIC_TAG_ENCODED_CBOR);
        mEncoder.startByteString(readerAuthLen);
        short payloadLen = (short) (readerAuthLen + (mEncoder.getCurrentOffset() - scratchStart));

        // Start encoding Sig Structure
        mEncoder.init(scratch, scratchStart, scratchLen);;
        // Array of 4
        mEncoder.startArray((short)4);
        // "Signature1"
        mEncoder.encodeRawData(SIGN1_Signature1, (short) 0, (short) SIGN1_Signature1.length);
        // Protected header Bytes with map with one element of algorithm
        byte[] cborAlg = mapAlgToCOSEAlg(alg);
        mEncoder.startByteString((short)cborAlg.length);
        mEncoder.encodeRawData(cborAlg, (short) 0, (short)cborAlg.length);
        // external aad
        mEncoder.startByteString((short)0);
        // payload
        mEncoder.startByteString(payloadLen);
        // payload is the detached content as follows
        // ReaderAuthenticationBytes - BStr with tag 24
        mEncoder.encodeTag((byte)MdlSpecifications.CBOR_SEMANTIC_TAG_ENCODED_CBOR);
        // start byte string
        mEncoder.startByteString(readerAuthLen);
        // ReaderAuthentication
        // Array of 3
        mEncoder.startArray((short) 3);
        // "ReaderAuthentication"
        mEncoder.encodeRawData(MdlSpecifications.readerAuthentication, (short) 0,
            (short) MdlSpecifications.readerAuthentication.length);
        // Now just digest this and then add Session Transcript and item bytes to the digest
        len = (short)(mEncoder.getCurrentOffset() - scratchStart);
        verifier.update(scratch, scratchStart, len);
        verifier.update(sessionTrans, sessionTransStart, sessionTransLen);
        boolean ret = verifier.verify(buf, itemsBytesStart, itemsBytesLen,sign, signStart,
            signLen);

        byte[] data = new byte[1024];
        short index = Util.arrayCopyNonAtomic(scratch, scratchStart, data, (short)0, len);
        index = Util.arrayCopyNonAtomic(sessionTrans, sessionTransStart, data, index,
            sessionTransLen);
        index = Util.arrayCopyNonAtomic(buf, itemsBytesStart, data, index,itemsBytesLen);
        SEProvider.print(data, (short)0, index);
        SEProvider.print(sign, signStart,signLen);

        return ret ;
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
        short itemsBytesStart, short itemsBytesLen,
        short readerAuthStart, short readerAuthLen,
        byte[] scratch, short scratchStart, short scratchLen){
        reset();
        // Perform readAuth
        if(!processReaderAuth(doc, tmpArray, buf, itemsBytesStart, itemsBytesLen,
        readerAuthStart, readerAuthLen, scratch, scratchStart,scratchLen)){
            return false;
        }
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
            mNsTable[(short)(mNsTableEnd + MdocPresentationPkg.NS_KEY_ID_OFFSET)] = nsKey;
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
                    mElementTable[(short)(mElementTableEnd + MdocPresentationPkg.ELEM_KEY_ID_OFFSET)] =
                        elemKey;
                    mElementTable[(short)(mElementTableEnd + MdocPresentationPkg.ELEM_START_OFFSET)] =
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
    private short getSessionTranscriptStart(byte[] sessionTransBytes, short currentStart,
        short len){
        // The digest includes session transcript and not the session transcript bytes. So decode
        // the session transcript from the transcript bytes.
        mDecoder.init(
            Session.mSessionTranscriptBytes, (short) 2, Util.getShort(Session.mSessionTranscriptBytes, (short) 0));
        mDecoder.readMajorType(CBORBase.TYPE_TAG);
        mDecoder.readMajorType(CBORBase.TYPE_BYTE_STRING);
        return mDecoder.getCurrentOffset();
    }

    private boolean processReaderAuth(MdocPresentationPkg doc, short[] tmpArray,
        byte[] buf, short itemsBytesStart, short itemsBytesLen,
        short readerAuth, short readerAuthLen,
        byte[] scratch, short scratchStart, short scratchLen) {
        // First check whether document requires reader authentication
        if(!doc.isReaderAuthRequired()){
            // If no reader auth is required then just return true.
            return true;
        }
        // Decode the reader Auth CoseSign1
        short signLen = decodeCoseSign1(buf, readerAuth, readerAuthLen, tmpArray,
            scratch, scratchStart);
        if(signLen < 0){
            return false;
        }
        // Extract the algorithm
        short alg = tmpArray[0];
        if(alg != SEProvider.ES256 && alg != SEProvider.ES384 && alg != SEProvider.ES512){
            return false;
        }

        // Perform X509 chain validation - this will return the public keys contained in the
        // certificate chain in the tmpArray.
        if(!X509CertHandler.validateChain(doc, buf, tmpArray,
            scratch, signLen, (short)(scratchLen - signLen))){
            return false;
        }

        short sessionTransLength = Util.getShort(Session.mSessionTranscriptBytes, (short) 0);
        // The session transcript in Session is tagged byte string so extract Session
        // Transcript array from it. This returns the start of this array.
        short sessionTransStart = getSessionTranscriptStart(Session.mSessionTranscriptBytes, (short) 2
            , sessionTransLength);
        // Adjust the transcript length - note 2 bytes at the beginning of the mSessionTranscript
        // stores length of the SessionTranscriptBytes.
        sessionTransLength -= (short) (sessionTransStart - 2);

        //Now perform the reader authentication
        return performReaderAuth(buf,
            itemsBytesStart, itemsBytesLen, // item bytes
            Session.mSessionTranscriptBytes, sessionTransStart, sessionTransLength,
            alg, // algorithm to use
            buf, tmpArray[1], tmpArray[0], // public key
            scratch, scratchStart, signLen, // signature to validate
            scratch, signLen, (short)(scratchLen - signLen) // scratch pad
        );
    }
    private static short mapAlg(short alg){
        switch(alg){
            case MdlSpecifications.ES256:
                return SEProvider.ES256;
            case MdlSpecifications.ES384:
                return SEProvider.ES384;
            case MdlSpecifications.ES512:
                return SEProvider.ES512;
        }
        return -1;
    }
    private short decodeCoseSign1(
        byte[] buf, short readerAuth, short readerAuthLen, short[] tmpArray,
        byte[] scratch, short scratchStart) {
        short signLen = -1;
        SEProvider.print(buf, readerAuth, readerAuthLen);
        mDecoder.init(buf, readerAuth, readerAuthLen);
        try{
        if(
            (mDecoder.readMajorType(CBORBase.TYPE_ARRAY) != 4) ||
            (mDecoder.readMajorType(CBORBase.TYPE_BYTE_STRING) <= 0)) {
                return -1;
            }
        // Read algorithm
        short elemCount= mDecoder.readMajorType(CBORBase.TYPE_MAP);
        boolean found = false;
        for(byte i = 0; i < elemCount; i++){
            if(found){
                mDecoder.skipEntry(); // skip key
                mDecoder.skipEntry(); // skip val
                continue;
            }
            short key = mDecoder.readInt8();
            if(key != (byte)0x01){
                mDecoder.skipEntry(); // skip value
            }else{
                found = true;
                short val = mDecoder.readInt8();
                tmpArray[0] = mapAlg(val);
                if(tmpArray[0] < 0){
                    return -1;
                }
            }
        }
        //Read certificates
            elemCount= mDecoder.readMajorType(CBORBase.TYPE_MAP);
            found = false;
            for(byte i = 0; i < elemCount; i++){
                if(found){
                    mDecoder.skipEntry(); // skip key
                    mDecoder.skipEntry(); // skip val
                    continue;
                }
                short key = mDecoder.readInt8();
                if(key != (byte)33){
                    mDecoder.skipEntry(); // skip value
                }else{
                    found = true;
                    short type = mDecoder.getMajorType();
                    if(type == CBORBase.TYPE_BYTE_STRING){
                        tmpArray[1] = 1;
                        tmpArray[2] = mDecoder.readMajorType(CBORBase.TYPE_BYTE_STRING);
                        tmpArray[3] = mDecoder.getCurrentOffset();
                        mDecoder.increaseOffset(tmpArray[2]);
                        SEProvider.print(buf, tmpArray[3], tmpArray[2]);
                    }else if(type == CBORBase.TYPE_ARRAY){
                        elemCount = mDecoder.readMajorType(CBORBase.TYPE_ARRAY);
                        tmpArray[1] = elemCount;
                        for(byte j = 1; j <= elemCount; j++){
                            short certLen =
                                mDecoder.readMajorType(CBORBase.TYPE_BYTE_STRING);
                            short certStart = tmpArray[3] = mDecoder.getCurrentOffset();
                            mDecoder.increaseOffset(certLen);
                            tmpArray[(short)(j * 2)] = certLen;
                            tmpArray[(short)(j * 3)] = certStart;
                        }
                    }else{
                        return -1;
                    }
                }
            }
            // Payload = null
            if(mDecoder.getRawByte() != (byte)0xF6){
                return -1;
            }
            mDecoder.increaseOffset((short)1);
            // Read signature
            signLen = mDecoder.readMajorType(CBORBase.TYPE_BYTE_STRING);
            mDecoder.readRawByteArray(scratch, scratchStart, signLen);
            SEProvider.print(scratch, scratchStart, signLen);
        }catch(ISOException exp){
            return -1;
        }
        return signLen;
    }
//    static final String testDeviceSessionTrans =
//        "83d8185858a20063312e30018201d818584ba4010220012158205a88d182bce5f42efa59943f33359d2e8a968ff289d93e5fa444b624343167fe225820b16e8cf858ddc7690407ba61d4c338237a8cfcf3de6aa672fc60a557aa32fc67d818584ba40102200121582060e3392385041f51403051f2415531cb56dd3f999c71687013aac6768bc8187e225820e58deb8fdbe907f7dd5368245551a34796f7d2215c440c339bb0f7b67beccdfa8258c391020f487315d10209616301013001046d646f631a200c016170706c69636174696f6e2f766e642e626c7565746f6f74682e6c652e6f6f6230081b28128b37282801021c015c1e580469736f2e6f72673a31383031333a646576696365656e676167656d656e746d646f63a20063312e30018201d818584ba4010220012158205a88d182bce5f42efa59943f33359d2e8a968ff289d93e5fa444b624343167fe225820b16e8cf858ddc7690407ba61d4c338237a8cfcf3de6aa672fc60a557aa32fc6758cd91022548721591020263720102110204616301013000110206616301036e6663005102046163010157001a201e016170706c69636174696f6e2f766e642e626c7565746f6f74682e6c652e6f6f6230081b28078080bf2801021c021107c832fff6d26fa0beb34dfcd555d4823a1c11010369736f2e6f72673a31383031333a6e66636e6663015a172b016170706c69636174696f6e2f766e642e7766612e6e616e57030101032302001324fec9a70b97ac9684a4e326176ef5b981c5e8533e5f00298cfccbc35e700a6b020414";
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


    private static byte[] tmpData;
    private static short tmpIndex;
    public boolean generateDeviceAuthMacTag(
        byte[] scratchPad, short start, short len) {
        // Initializes mDeviceAuth - this is HMac Signer.
        initDeviceAuth(this, scratchPad, start, len);
        // Create Mac Structure to generate CoseMac0.
        // Digest the partial Mac0 structure
        mDeviceAuth.update(MAC0_STRUCT, (short) 0, (short) MAC0_STRUCT.length);
        tmpData = new byte[2948];
        tmpIndex = Util.arrayCopyNonAtomic(MAC0_STRUCT, (short) 0, tmpData, (short)0,
            (short) MAC0_STRUCT.length);
        SEProvider.print(tmpData,(short) 0, tmpIndex);

        // Now add detached content which is tagged binary string and hence we need to know the
        // length before we can encode and digest it.
        // Calculate the length.
        byte[] session = Session.mSessionTranscriptBytes;
        short sessionTransLength = Util.getShort(Session.mSessionTranscriptBytes, (short) 0);
        short sessionTransStart = getSessionTranscriptStart(Session.mSessionTranscriptBytes, (short) 2
            , sessionTransLength);
        sessionTransLength -= (short) (sessionTransStart - 2);

        SEProvider.print(Session.mSessionTranscriptBytes, (short) 2, sessionTransLength);
        short docTypeLength = ((MdocPresentationPkg) mPresentationPkg[0]).getDocType(scratchPad, start);
        short detachedContentLen = (short) (
            //Cbor array with 4 elements (1)
            1 +
            // "DeviceAuthentication" text string
            (short) MdlSpecifications.deviceAuthentication.length +
            // Cbor Encoded Session Transcript length
                sessionTransLength +
            // doc type length
            docTypeLength +
                (short)4); // no namespaces thus only 3 bytes of header
        short detachedContentBytesLen = detachedContentLen;
        // Now we can encode and digest the detached content
        mEncoder.init(scratchPad, start, len);
        if(detachedContentBytesLen < CBORBase.ENCODED_ONE_BYTE){
            detachedContentBytesLen += 3;// SemTag (2) + bStr(1)
        }else if(detachedContentBytesLen < (short) 0x100){
            detachedContentBytesLen += 4; //// SemTag (2) + bStr(2)
        }else if(detachedContentBytesLen <= (short) 0x7FFF){
            detachedContentBytesLen += 5; //// SemTag (2) + bStr(3)
        }else{
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        mEncoder.startByteString(detachedContentBytesLen);
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
        tmpIndex = Util.arrayCopyNonAtomic(scratchPad, start, tmpData, tmpIndex,
            (short) (mEncoder.getCurrentOffset() - start));
        SEProvider.print(tmpData,(short) 0, tmpIndex);
        // Element 2: Session transcript
        mDeviceAuth.update(session, sessionTransStart, sessionTransLength);
        SEProvider.print(session,sessionTransStart, sessionTransLength);
        tmpIndex = Util.arrayCopyNonAtomic(session, sessionTransStart,tmpData, tmpIndex,
            sessionTransLength);
        // Element 3: doc type
        ((MdocPresentationPkg) mPresentationPkg[0]).getDocType(scratchPad, start);
        mDeviceAuth.update(scratchPad, start, docTypeLength);
        tmpIndex = Util.arrayCopyNonAtomic(scratchPad, start, tmpData, tmpIndex, docTypeLength);
        // Element 4: Encode and digest document name spaces - current it will be always zero
        mEncoder.init(scratchPad, start, len);
        mEncoder.encodeTag((byte)MdlSpecifications.CBOR_SEMANTIC_TAG_ENCODED_CBOR);
        mEncoder.startByteString((short) 1);
        mEncoder.startMap((short) 0);
        mDeviceAuth.update(scratchPad, start, (short) (mEncoder.getCurrentOffset() - start));

        // Now generate the mac tag
        mEncoder.init(mMacTag, (short)0, (short)mMacTag.length);
        mEncoder.startByteString( MdlSpecifications.CBOR_MAC_TAG_SIZE);
        if(mDeviceAuth.sign(scratchPad, start, (short)0, mMacTag, (short)2)
            != MdlSpecifications.CBOR_MAC_TAG_SIZE){
            return false;
        }
        //System.out.println("Device Side - Device Auth Mac Tag:");
        SEProvider.print(mMacTag, (short)0, (short) mMacTag.length);
        return true;
    }
    void initDeviceAuth(DocumentRequest request, byte[] scratch, short start, short len){
        // Derive Device Secret for mdoc signing
        ECPrivateKey devicePrivKey = (ECPrivateKey)request.getDocument().getAuthKeyPair().getPrivate();
        mKeyAgreement.init(devicePrivKey);
        short pubLen = Session.mEReaderKeyPub.getW(scratch, start);
        short secretStart = (short) (start + pubLen);
        short secretLen = mKeyAgreement.generateSecret(scratch, start, pubLen, scratch,
            secretStart);
        SEProvider.print(scratch, secretStart, secretLen);
        short saltStart = (short) (secretStart + secretLen);
        short saltLen = (short) Session.mSalt.length;
        SEProvider.print(Session.mSalt, (short) 0, saltLen);
        short outStart = Util.arrayCopyNonAtomic(Session.mSalt, (short) 0, scratch, saltStart,
            saltLen);
        short outLen = Session.hkdf(scratch, saltStart, saltLen, scratch, secretStart, secretLen,
            MdlSpecifications.eMacKey,scratch, outStart);
        //System.out.println("Device Side Device EMacKey:");
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
        digest.update(scratch, start, (short) (mEncoder.getCurrentOffset() - start));
        tmpIndex = Util.arrayCopyNonAtomic(scratch, start, tmpData, tmpIndex,
            (short) (mEncoder.getCurrentOffset() - start));
        dataLen += (short) (mEncoder.getCurrentOffset() - start);
        for(byte i = 0; i < nsTableSize; i+=MdocPresentationPkg.NS_TABLE_ROW_SIZE){
            mEncoder.init(scratch,start,len);
            short nsId = nsTable[(short)(i+MdocPresentationPkg.NS_KEY_ID_OFFSET)];
            byte[] nsStr = MdlSpecifications.getDocNameSpaceString(nsId);
            SEProvider.print(nsStr, (short)0, (short)nsStr.length);
            mEncoder.encodeRawData(nsStr,(short)0, (short) nsStr.length);
            short elemTableSize = request.getElementCountForNs(i);
            mEncoder.startMap(elemTableSize);
            digest.update(scratch, start, (short) (mEncoder.getCurrentOffset() - start));
            tmpIndex = Util.arrayCopyNonAtomic(scratch, start, tmpData, tmpIndex,
                (short) (mEncoder.getCurrentOffset() - start));
            dataLen += (short) (mEncoder.getCurrentOffset() - start);
            for(byte j = 0; j < elemTableSize; j++){
                short offset = (short)(j* MdocPresentationPkg.ELEM_TABLE_ROW_SIZE);
                short elemId =
                    elemTable[(short)( offset+ MdocPresentationPkg.ELEM_KEY_ID_OFFSET)];
                byte[] elemIdStr = MdlSpecifications.getNameSpaceElements_Mdl(elemId);
                SEProvider.print(elemIdStr, (short)0, (short)elemIdStr.length);
                digest.update(elemIdStr, (short)0, (short) elemIdStr.length);
                tmpIndex = Util.arrayCopyNonAtomic(elemIdStr, (short) 0, tmpData, tmpIndex,
                    (short) elemIdStr.length);
                dataLen += (short)elemIdStr.length;
                digest.update(pkg.getBuffer(),
                        elemTable[(short)(offset + MdocPresentationPkg.ELEM_VALUE_START_OFFSET)],
                        elemTable[(short)(offset + MdocPresentationPkg.ELEM_VALUE_LENGTH_OFFSET)]);
                tmpIndex = Util.arrayCopyNonAtomic(pkg.getBuffer(),
                    elemTable[(short)(offset + MdocPresentationPkg.ELEM_VALUE_START_OFFSET)], tmpData, tmpIndex,
                    elemTable[(short)(offset + MdocPresentationPkg.ELEM_VALUE_LENGTH_OFFSET)]);
                dataLen += elemTable[(short)(offset + MdocPresentationPkg.ELEM_VALUE_LENGTH_OFFSET)];
            }
        }
        return dataLen;
    }
    short getNsCount(){
        return (short) (getNsTableEnd()/ MdocPresentationPkg.NS_TABLE_ROW_SIZE);
    }
    short getElementCountForNs(short nsIndex){
        nsIndex = (short) (nsIndex * MdocPresentationPkg.NS_TABLE_ROW_SIZE);
        short start = mNsTable[(short)(nsIndex + MdocPresentationPkg.NS_START_OFFSET)];
        short end  = mNsTable[(short)(nsIndex + MdocPresentationPkg.NS_END_OFFSET)];
        return (short) ((short)(end - start) / MdocPresentationPkg.ELEM_TABLE_ROW_SIZE);
    }

    public short getElementStart(short nsIndex, short elemIndex) {
        nsIndex = (short)(nsIndex * MdocPresentationPkg.NS_TABLE_ROW_SIZE);
        short elemTableStart = mNsTable[(short)(nsIndex + MdocPresentationPkg.NS_START_OFFSET)];
        elemIndex = (short)((elemIndex * MdocPresentationPkg.ELEM_TABLE_ROW_SIZE) + elemTableStart);
        return mElementTable[(short)(elemIndex +  MdocPresentationPkg.ELEM_START_OFFSET)];
    }

    public short getElementLen(short nsIndex, short elemIndex) {
        nsIndex = (short)(nsIndex * MdocPresentationPkg.NS_TABLE_ROW_SIZE);
        short elemTableStart = mNsTable[(short)(nsIndex + MdocPresentationPkg.NS_START_OFFSET)];
        elemIndex = (short)((elemIndex * MdocPresentationPkg.ELEM_TABLE_ROW_SIZE) + elemTableStart);
        return mElementTable[(short)(elemIndex +  MdocPresentationPkg.ELEM_LENGTH_OFFSET)];
    }

    public byte[] getNsId(short nsIndex) {
        nsIndex = (short)(nsIndex * MdocPresentationPkg.NS_TABLE_ROW_SIZE);
        short nsId = mNsTable[(short)(nsIndex + MdocPresentationPkg.NS_KEY_ID_OFFSET)];
        return MdlSpecifications.getDocNameSpaceString(nsId);
    }



    private static byte[] mapAlgToCOSEAlg(short alg){
        switch(alg){
            case SEProvider.ES256:
                return SIGN1_ALG_ES256;
            case SEProvider.ES384:
                return SIGN1_ALG_ES384;
        }
        return null;
    }
}
