package com.android.javacard.mdl;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.KeyBuilder;

public class MdlSpecifications {

  // Doc types
  // Reserved doc type
  public static final short KEY_MAIN_DOC_TYPE = 0;

  // Mdl doc type
  // Text String with "org.iso.18013.5.1.mDL"
  public static final byte[] mdlDocType = {0x75,
      0x6f, 0x72, 0x67, 0x2e, 0x69, 0x73, 0x6f, 0x2e, 0x31, 0x38, 0x30, 0x31, 0x33, 0x2e, 0x35,
      0x2e, 0x31, 0x2e, 0x6d, 0x44, 0x4c,
  };
  public static final short KEY_MDL_DOC_TYPE = 1;

  public static final short[] DOC_TYPES = {
      KEY_MAIN_DOC_TYPE,
      KEY_MDL_DOC_TYPE,
  };
  public static final short CBOR_MAC_TAG_SIZE = 32;
  // CBOR constants - TODO remove the following and use CBORBase instead
  public static final short CBOR_UINT8_LENGTH =  0x18;
  public static final short CBOR_UINT16_LENGTH =  0x19;
  public static final short CBOR_UINT32_LENGTH = 0x1A;
  public static final short CBOR_UINT64_LENGTH =  0x1B;
  public static final short CBOR_ANY = 0x0100;
  public static final short CBOR_BOOL = 0xF0;
  public static final short CBOR_NIL = 0xF6;
  public static final short CBOR_TRUE = 0xF5;
  public static final short CBOR_FALSE = 0xF4;

  public static final short CBOR_MAP = 0xA0;
  public static final short CBOR_ARRAY = 0x80;
  public static final short CBOR_TEXT_STR = 0x60;
  public static final short CBOR_NEG_INT = 0x20;
  public static final short CBOR_UINT = 0;
  public static final short CBOR_SEMANTIC_TAG = 0xC0;
  public static final short CBOR_SEMANTIC_TAG_ENCODED_CBOR = 24;
  public static final short CBOR_MAX_256_BYTES = 0x18; //24
  public static final short CBOR_MAX_64K_BYTES = 0x19; //25
  static final short CBOR_ADDITIONAL_MASK = 0x1F;
  public static final short CBOR_MAJOR_TYPE_MASK = 0xE0;
  public static final short CBOR_BINARY_STR = 0x40;

  //Name Spaces
  //Reserved name space
  public static final byte KEY_MAIN_NAMESPACE = 0;

  // Mdl Name space
  //"org.iso.18013.5.1" - nameSpaces
  public static final byte[] mdlNameSpace = {0x71,
      0x6F, 0x72, 0x67, 0x2E, 0x69, 0x73, 0x6F, 0x2E, 0x31, 0x38, 0x30, 0x31, 0x33, 0x2E, 0x35,
      0x2E,0x31};

  // HAL Commands related keys CBOR Uint < 23
  public static final byte HAL_KEY_OFFSET = 0;
  public static final byte KEY_ENC_DATA = (byte)(HAL_KEY_OFFSET+0);
  public static final byte KEY_CERT = (byte)(HAL_KEY_OFFSET+1);
  public static final byte KEY_HAL_CMD_DOC_SLOT = (byte)(HAL_KEY_OFFSET+2);
  public static final byte KEY_TEST_CREDENTIAL = (byte)(HAL_KEY_OFFSET+3);
  public static final byte KEY_CRED_CERT_CHALLENGE = (byte)(HAL_KEY_OFFSET+4);
  public static final byte KEY_HAL_CMD_DOC_TYPE = (byte)(HAL_KEY_OFFSET+5);
  public static final byte KEY_HAL_CMD_MDOC_NUM_SIGN_KEYS = (byte)(HAL_KEY_OFFSET+6);
  public static final byte KEY_HAL_CMD_MDOC_USERS_PER_SIGN_KEY = (byte)(HAL_KEY_OFFSET+7);
  public static final byte KEY_HAL_CMD_MDOC_VALID_TIME = (byte)(HAL_KEY_OFFSET+8);
  public static final byte KEY_OPERATION = (byte)(HAL_KEY_OFFSET+9);
  public static final byte KEY_CRED_DATA = (byte)(HAL_KEY_OFFSET+10);
  public static final byte KEY_READER_ACCESS = (byte)(HAL_KEY_OFFSET+11);
  public static final byte KEY_KEY_PARAMS = (byte)(HAL_KEY_OFFSET+12);
  public static final byte KEY_ATTEST_KEY_PARAMS = (byte)(HAL_KEY_OFFSET+13);
  public static final byte KEY_ATTEST_KEY_BLOB = (byte)(HAL_KEY_OFFSET+14);

  // main name space elements
  // Standard CBOR type indexes
  public static final short IND_KEY_OFFSET = 16;
  public static final short IND_UINT_TYPE = (short) (IND_KEY_OFFSET + 0);
  public static final short IND_TXT_STR_TYPE = (short) (IND_KEY_OFFSET + 1);
  public static final short IND_BINARY_STR_TYPE = (short) (IND_KEY_OFFSET + 2);
  public static final short IND_ARRAY_TYPE= (short) (IND_KEY_OFFSET + 3);
  public static final short IND_SESSION_ESTABLISHMENT = (short) (IND_KEY_OFFSET + 4);
  public static final short IND_SESSION_DATA = (short) (IND_KEY_OFFSET + 5);
  public static final short IND_MDOC = (short) (IND_KEY_OFFSET + 6);
  public static final short IND_STATIC_AUTH_DATA = (short) (IND_KEY_OFFSET + 7);
  public static final short IND_ISSUER_SIGNED_ITEM = (short) (IND_KEY_OFFSET + 8);
  public static final short IND_CRED_DATA_DIGEST_MAPPING = (short)(IND_KEY_OFFSET + 9);
  public static final short  IND_MDOC_HAL_CMD= (short)(IND_KEY_OFFSET + 10);

  // key strings and uint indexes
  public static final short MDL_KEY_OFFSET = 32;
  public static final short KEY_EREADER_KEY = (short) MDL_KEY_OFFSET;
  public static final short KEY_DEVICE_REQUEST = (short) (MDL_KEY_OFFSET + 1);
  public static final short KEY_STATUS = (short) (MDL_KEY_OFFSET + 2);
  public static final short KEY_VERSION = (short)(MDL_KEY_OFFSET + 3);
  public static final short KEY_DOC_REQUESTS = (short)(MDL_KEY_OFFSET + 4);
  public static final short KEY_COSE_KTY = (short)(MDL_KEY_OFFSET + 5);
  public static final short KEY_COSE_CRV = (short) (MDL_KEY_OFFSET + 6);
  public static final short KEY_COSE_X_COORD = (short) (MDL_KEY_OFFSET + 7);
  public static final short KEY_COSE_Y_COORD = (short) (MDL_KEY_OFFSET + 8);
  public static final short KEY_DOC_TYPE = (short) (MDL_KEY_OFFSET + 9);
  public static final short KEY_ISSUER_SIGNED = (short) (MDL_KEY_OFFSET + 10);
  public static final short KEY_DEVICE_SIGNED = (short) (MDL_KEY_OFFSET + 11);
  public static final short KEY_ERRORS= (short) (MDL_KEY_OFFSET + 12);
  public static final short KEY_NAME_SPACES= (short) (MDL_KEY_OFFSET + 13);
  public static final short KEY_DEVICE_AUTH= (short) (MDL_KEY_OFFSET + 14);
  public static final short KEY_COSE_SIGN_ALG= (short) (MDL_KEY_OFFSET + 15);
  public static final short KEY_ITEMS_REQUEST= (short) (MDL_KEY_OFFSET + 16);
  public static final short KEY_READER_AUTH= (short) (MDL_KEY_OFFSET + 17);
  public static final short KEY_DEVICE_SIGNATURE= (short) (MDL_KEY_OFFSET + 18);
  public static final short KEY_DEVICE_MAC= (short) (MDL_KEY_OFFSET + 19);
  public static final short KEY_REQUEST_INFO= (short) (MDL_KEY_OFFSET + 20);
  public static final short KEY_DIGEST_MAPPING = (short) (MDL_KEY_OFFSET + 21);
  public static final short KEY_DIGEST_ID= (short) (MDL_KEY_OFFSET + 22);
  public static final short KEY_ELEM_ID= (short) (MDL_KEY_OFFSET + 23);
  public static final short KEY_ELEM_VAL= (short) (MDL_KEY_OFFSET + 24);
  public static final short KEY_ISSUER_AUTH = (short)(MDL_KEY_OFFSET + 25);
  public static final short KEY_RANDOM = (short)(MDL_KEY_OFFSET + 26);
  public static final short KEY_ISSUER_NS = (short)(MDL_KEY_OFFSET + 27);

  // Fixed arrays of strings - along with text string header
  //"eReaderKey"
  public static final byte[] session_eReaderKey = {0x6A,
      0x65, 0x52, 0x65, 0x61, 0x64, 0x65, 0x72, 0x4b, 0x65, 0x79};
  //"status"
  public static final byte[] status = {0x66,
      0x73, 0x74, 0x61, 0x74, 0x75, 0x73};
  //"version"
  public static final byte[] version = {0x67,
      0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e};
  // "data"
  public static final byte[] session_data = {0x64,
      0x64, 0x61, 0x74, 0x61};
  // "docRequests"
  public static final byte[] docRequests = {0x6B,
      0x64, 0x6f, 0x63, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x73};
  //"docType"
  public static final byte[] docType = {0x67,
      0x64, 0x6f, 0x63, 0x54, 0x79, 0x70, 0x65};
  //"issuerSigned"
  public static final byte[] issuerSigned = {0x6C,
      0x69, 0x73, 0x73, 0x75, 0x65, 0x72, 0x53, 0x69, 0x67, 0x6e, 0x65, 0x64};
  //"issuerAuth"
  public static final byte[] issuerAuth = {0x6A,
      0x69, 0x73, 0x73, 0x75, 0x65, 0x72, 0x41, 0x75, 0x74, 0x68};
  //"deviceSigned"
  public static final byte[] deviceSigned = {0x6C,
      0x64, 0x65, 0x76, 0x69, 0x63, 0x65, 0x53, 0x69, 0x67, 0x6e, 0x65, 0x64};
  //"errors"
  public static final byte[] errors = {0x66,
      0x65, 0x72, 0x72, 0x6F, 0x72, 0x73};
  //"nameSpaces"
  public static final byte[] nameSpaces = {0x6A,
      0x6e, 0x61, 0x6d, 0x65, 0x53, 0x70, 0x61, 0x63, 0x65, 0x73};
  //"deviceAuth"
  public static final byte[] deviceAuth = {0x6A,
      0x64, 0x65, 0x76, 0x69, 0x63, 0x65, 0x41, 0x75, 0x74, 0x68};
  //"readerAuth"
  public static final byte[] readerAuth = {0x6A,
      0x72, 0x65, 0x61, 0x64, 0x65, 0x72, 0x41, 0x75, 0x74, 0x68};
  //"itemsRequest"
  public static final byte[] itemsRequest = {0x6C,
      0x69, 0x74, 0x65, 0x6d, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74};
  //"requestInfo"
  public static final byte[] requestInfo = {0x6B,
      0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x49, 0x6e, 0x66, 0x6f};
  //"deviceSignature"
  public static final byte[] deviceSignature = {0x6F,
      0x64, 0x65, 0x76, 0x69, 0x63, 0x65, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65};
  //"deviceMac"
  public static final byte[] deviceMac = {0x69,
      0x64, 0x65, 0x76, 0x69, 0x63, 0x65, 0x4d, 0x61, 0x63};
  //"ES256"
  public static final byte[] es256 = {0x65,
      0x45, 0x53, 0x32, 0x35, 0x36};
  //"DeviceAuthentication"
  public static final byte[] deviceAuthentication = {0x74,
      0x44, 0x65, 0x76, 0x69, 0x63, 0x65, 0x41, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63,
      0x61, 0x74, 0x69, 0x6f, 0x6e};
  //"EMacKey"
  public static final byte[] eMacKey = {0x67,
      0x45, 0x4d, 0x61, 0x63, 0x4b, 0x65, 0x79};
  //"digestIdMapping"
  public static final byte[] digestIdMapping = { 0x6F,
      0x64,0x69,0x67,0x65,0x73,0x74,0x49,0x64,0x4d,0x61,0x70,0x70,0x69,0x6e,0x67};
  //"issuerNameSpaces"
  public static final byte[] issuerNameSpaces = { 0x70,
      0x69,0x73,0x73,0x75,0x65,0x72,0x4e,0x61,0x6d,0x65,0x53,0x70,0x61,0x63,0x65,0x73,
  };
  //"digestID"
  public static final byte[] digestID = { 0x68,
      0x64,0x69,0x67,0x65,0x73,0x74,0x49,0x44};
  //"random"
  public static final byte[] random = {0x66,
      0x72,0x61,0x6E,0x64,0x6F,0x6D};
  //"elementIdentifier"
  public static final byte[] elementIdentifier ={0x71,
      0x65,0x6C,0x65,0x6D,0x65,0x6E,0x74,0x49,0x64,0x65,0x6E,0x74,0x69,0x66,0x69,0x65,0x72};
  //"elementValue"
  public static final byte[] elementValue ={0x6C,
      0x65,0x6C,0x65,0x6D,0x65,0x6E,0x74,0x56,0x61,0x6C,0x75,0x65,
  };
  // Following are used in HKDF key derivation - so they are not text strings
  // "SKDevice"
  public static final byte[] deviceSecretInfo = {0x53, 0x4b, 0x44, 0x65, 0x76, 0x69, 0x63, 0x65};
  // "SKReader"
  public static final byte[] readerSecretInfo = {0x53, 0x4b, 0x52, 0x65, 0x61, 0x64, 0x65, 0x72};
  // "readerAccess"
  public static final byte[] readerAccess = {0x6C,
      0x72, 0x65, 0x61, 0x64, 0x65, 0x72, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73};
  public static final byte KEY_MDL_NAMESPACE = 1;

  public static final short[] NAMESPACES = {
//      KEY_MAIN_NAMESPACE, CBOR_ARRAY,
      KEY_MDL_NAMESPACE, CBOR_ARRAY,
  };

  //"org.iso.18013.5.1" - nameSpace elements
  public static final short KEY_ELEM_FAMILY_NAME =  1;
  public static final short KEY_ELEM_GIVEN_NAME =  2;
  public static final short KEY_ELEM_BIRTH_DATE =  3;
  public static final short KEY_ELEM_ISSUE_DATE =  4;
  public static final short KEY_ELEM_EXPIRY_DATE =  5;
  public static final short KEY_ELEM_ISSUING_COUNTRY =  6;
  public static final short KEY_ELEM_ISSUING_AUTHORITY =  7;
  public static final short KEY_ELEM_DOCUMENT_NUMBER =  8;
  public static final short KEY_ELEM_PORTRAIT =  9;
  public static final short KEY_ELEM_DRIVING_PRIVILEGES =  10;
  public static final short KEY_ELEM_UN_DISTINGUISHING_SIGN =  11;
  public static final short KEY_ELEM_ADMINISTRATIVE_NUMBER =  12;
  public static final short KEY_ELEM_SEX =  13;
  public static final short KEY_ELEM_HEIGHT =  14;
  public static final short KEY_ELEM_WEIGHT =  15;
  public static final short KEY_ELEM_EYE_COLOUR =  16;
  public static final short KEY_ELEM_HAIR_COLOUR =  17;
  public static final short KEY_ELEM_BIRTH_PLACE =  18;
  public static final short KEY_ELEM_RESIDENT_ADDRESS =  19;
  public static final short KEY_ELEM_PORTRAIT_CAPTURE_DATE =  20;
  public static final short KEY_ELEM_AGE_IN_YEARS =  21;
  public static final short KEY_ELEM_AGE_BIRTH_YEAR =  22;
  public static final short KEY_ELEM_AGE_OVER_NN =  23;
  public static final short KEY_ELEM_ISSUING_JURISDICTION =  24;
  public static final short KEY_ELEM_NATIONALITY =  25;
  public static final short KEY_ELEM_RESIDENT_CITY =  26;
  public static final short KEY_ELEM_RESIDENT_STATE =  27;
  public static final short KEY_ELEM_RESIDENT_POSTAL_CODE =  28;
  public static final short KEY_ELEM_RESIDENT_COUNTRY =  29;
  public static final short KEY_ELEM_BIOMETRIC_TEMPLATE_XX =  30;
  public static final short KEY_ELEM_FAMILY_NAME_NATIONAL_CHARACTER =  31;
  public static final short KEY_ELEM_GIVEN_NAME_NATIONAL_CHARACTER =  32;
  public static final short KEY_ELEM_SIGNATURE_USUAL_MARK =  33;

  public static final short[] STRUCT_MDL_NAME_SPACE_ELEMENTS = {
   KEY_ELEM_FAMILY_NAME, CBOR_MAP,
   KEY_ELEM_GIVEN_NAME, CBOR_MAP,
   KEY_ELEM_BIRTH_DATE, CBOR_MAP,
   KEY_ELEM_ISSUE_DATE, CBOR_MAP,
   KEY_ELEM_EXPIRY_DATE, CBOR_MAP,
   KEY_ELEM_ISSUING_COUNTRY, CBOR_MAP,
   KEY_ELEM_ISSUING_AUTHORITY, CBOR_MAP,
   KEY_ELEM_DOCUMENT_NUMBER, CBOR_MAP,
   KEY_ELEM_PORTRAIT, CBOR_MAP,
   KEY_ELEM_DRIVING_PRIVILEGES, CBOR_MAP,
   KEY_ELEM_UN_DISTINGUISHING_SIGN, CBOR_MAP,
   KEY_ELEM_ADMINISTRATIVE_NUMBER, CBOR_MAP,
   KEY_ELEM_SEX, CBOR_MAP,
   KEY_ELEM_HEIGHT, CBOR_MAP,
   KEY_ELEM_WEIGHT, CBOR_MAP,
   KEY_ELEM_EYE_COLOUR, CBOR_MAP,
   KEY_ELEM_HAIR_COLOUR, CBOR_MAP,
   KEY_ELEM_BIRTH_PLACE, CBOR_MAP,
   KEY_ELEM_RESIDENT_ADDRESS, CBOR_MAP,
   KEY_ELEM_PORTRAIT_CAPTURE_DATE, CBOR_MAP,
   KEY_ELEM_AGE_IN_YEARS, CBOR_MAP,
   KEY_ELEM_AGE_BIRTH_YEAR, CBOR_MAP,
   KEY_ELEM_AGE_OVER_NN, CBOR_MAP,
   KEY_ELEM_ISSUING_JURISDICTION, CBOR_MAP,
   KEY_ELEM_NATIONALITY, CBOR_MAP,
   KEY_ELEM_RESIDENT_CITY, CBOR_MAP,
   KEY_ELEM_RESIDENT_STATE, CBOR_MAP,
   KEY_ELEM_RESIDENT_POSTAL_CODE, CBOR_MAP,
   KEY_ELEM_RESIDENT_COUNTRY, CBOR_MAP,
   KEY_ELEM_BIOMETRIC_TEMPLATE_XX, CBOR_MAP,
   KEY_ELEM_FAMILY_NAME_NATIONAL_CHARACTER, CBOR_MAP,
   KEY_ELEM_GIVEN_NAME_NATIONAL_CHARACTER, CBOR_MAP,
   KEY_ELEM_SIGNATURE_USUAL_MARK, CBOR_MAP,
  };

  //"family_name"
  public static final byte[] family_name = {0x6b,
      0x66, 0x61, 0x6d, 0x69, 0x6c, 0x79, 0x5f, 0x6e, 0x61, 0x6d, 0x65,

  };

  //"given_name"
  public static final byte[] given_name = {0x6a,
      0x67, 0x69, 0x76, 0x65, 0x6e, 0x5f, 0x6e, 0x61, 0x6d, 0x65,
  };

  //"birth_date"
  public static final byte[] birth_date = {0x6a,
      0x62, 0x69, 0x72, 0x74, 0x68, 0x5f, 0x64, 0x61, 0x74, 0x65,
  };

  //"issue_date"
  public static final byte[] issue_date = {0x6a,
      0x69, 0x73, 0x73, 0x75, 0x65, 0x5f, 0x64, 0x61, 0x74, 0x65,
  };

  //"expiry_date"
  public static final byte[] expiry_date = {0x6b,
      0x65, 0x78, 0x70, 0x69, 0x72, 0x79, 0x5f, 0x64, 0x61, 0x74, 0x65,

  };

  //"issuing_country"
  public static final byte[] issuing_country = {0x6f,
      0x69, 0x73, 0x73, 0x75, 0x69, 0x6e, 0x67, 0x5f, 0x63, 0x6f, 0x75,
      0x6e, 0x74, 0x72, 0x79,
  };

  //"issuing_authority"
  public static final byte[] issuing_authority = {0x71,
      0x69, 0x73, 0x73, 0x75, 0x69, 0x6e, 0x67, 0x5f, 0x61, 0x75, 0x74,
      0x68, 0x6f, 0x72, 0x69, 0x74, 0x79,
  };

  //"document_number"
  public static final byte[] document_number = {0x6f,
      0x64, 0x6f, 0x63, 0x75, 0x6d, 0x65, 0x6e, 0x74, 0x5f, 0x6e, 0x75,
      0x6d, 0x62, 0x65, 0x72,
  };
  //"documents"
  public static byte[] documents ={0x69,
      0x64, 0x6f, 0x63, 0x75, 0x6d, 0x65, 0x6e, 0x74, 0x73,
  };

  //"portrait"
  public static final byte[] portrait = {0x68,
      0x70, 0x6f, 0x72, 0x74, 0x72, 0x61, 0x69, 0x74,
  };

  //"driving_privileges"
  public static final byte[] driving_privileges = {0x72,
      0x64, 0x72, 0x69, 0x76, 0x69, 0x6e, 0x67, 0x5f, 0x70, 0x72, 0x69,
      0x76, 0x69, 0x6c, 0x65, 0x67, 0x65, 0x73,
  };

  //"un_distinguishing_sign"
  public static final byte[] un_distinguishing_sign = {0x76,
      0x75, 0x6e, 0x5f, 0x64, 0x69, 0x73, 0x74, 0x69, 0x6e, 0x67, 0x75,
      0x69, 0x73, 0x68, 0x69, 0x6e, 0x67, 0x5f, 0x73, 0x69, 0x67, 0x6e,
  };

  //"administrative_number"
  public static final byte[] administrative_number = {0x75,
      0x61, 0x64, 0x6d, 0x69, 0x6e, 0x69, 0x73, 0x74, 0x72, 0x61, 0x74,
      0x69, 0x76, 0x65, 0x5f, 0x6e, 0x75, 0x6d, 0x62, 0x65, 0x72,
  };

  //"sex"
  public static final byte[] sex = {0x63,
      0x73, 0x65, 0x78,
  };

  //"height"
  public static final byte[] height = {0x66,
      0x68, 0x65, 0x69, 0x67, 0x68, 0x74,
  };

  //"weight"
  public static final byte[] weight = {0x66,
      0x77, 0x65, 0x69, 0x67, 0x68, 0x74,
  };

  //"eye_colour"
  public static final byte[] eye_colour = {0x6a,
      0x65, 0x79, 0x65, 0x5f, 0x63, 0x6f, 0x6c, 0x6f, 0x75, 0x72,
  };

  //"hair_colour"
  public static final byte[] hair_colour = {0x6b,
      0x68, 0x61, 0x69, 0x72, 0x5f, 0x63, 0x6f, 0x6c, 0x6f, 0x75, 0x72,
  };

  //"birth_place"
  public static final byte[] birth_place = {0x6b,
      0x62, 0x69, 0x72, 0x74, 0x68, 0x5f, 0x70, 0x6c, 0x61, 0x63, 0x65,
  };

  //"resident_address"
  public static final byte[] resident_address = {0x70,
      0x72, 0x65, 0x73, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x5f, 0x61, 0x64,
      0x64, 0x72, 0x65, 0x73, 0x73,
  };

  //"portrait_capture_date"
  public static final byte[] portrait_capture_date = {0x75,
      0x70, 0x6f, 0x72, 0x74, 0x72, 0x61, 0x69, 0x74, 0x5f, 0x63, 0x61,
      0x70, 0x74, 0x75, 0x72, 0x65, 0x5f, 0x64, 0x61, 0x74, 0x65,
  };

  //"age_in_years"
  public static final byte[] age_in_years = {0x6c,
      0x61, 0x67, 0x65, 0x5f, 0x69, 0x6e, 0x5f, 0x79, 0x65, 0x61, 0x72,
      0x73,
  };

  //"age_birth_year"
  public static final byte[] age_birth_year = {0x6e,
      0x61, 0x67, 0x65, 0x5f, 0x62, 0x69, 0x72, 0x74, 0x68, 0x5f, 0x79,
      0x65, 0x61, 0x72,
  };

  //"age_over_NN"
  public static final byte[] age_over_NN = {0x6b,
      0x61, 0x67, 0x65, 0x5f, 0x6f, 0x76, 0x65, 0x72, 0x5f, 0x4e, 0x4e,
  };

  //"issuing_jurisdiction"
  public static final byte[] issuing_jurisdiction = {0x74,
      0x69, 0x73, 0x73, 0x75, 0x69, 0x6e, 0x67, 0x5f, 0x6a, 0x75, 0x72,
      0x69, 0x73, 0x64, 0x69, 0x63, 0x74, 0x69, 0x6f, 0x6e,
  };

  //"nationality"
  public static final byte[] nationality = {0x6b,
      0x6e, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x61, 0x6c, 0x69, 0x74, 0x79,
  };

  //"resident_city"
  public static final byte[] resident_city = {0x6d,
      0x72, 0x65, 0x73, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x5f, 0x63, 0x69,
      0x74, 0x79,
  };

  //"resident_state"
  public static final byte[] resident_state = {0x6e,
      0x72, 0x65, 0x73, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x5f, 0x73, 0x74,
      0x61, 0x74, 0x65,
  };

  //"resident_postal_code"
  public static final byte[] resident_postal_code = {0x74,
      0x72, 0x65, 0x73, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x5f, 0x70, 0x6f,
      0x73, 0x74, 0x61, 0x6c, 0x5f, 0x63, 0x6f, 0x64, 0x65,
  };

  //"resident_country"
  public static final byte[] resident_country = {0x70,
      0x72, 0x65, 0x73, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x5f, 0x63, 0x6f,
      0x75, 0x6e, 0x74, 0x72, 0x79,
  };

  //"biometric_template_xx"
  public static final byte[] biometric_template_xx = {0x75,
      0x62, 0x69, 0x6f, 0x6d, 0x65, 0x74, 0x72, 0x69, 0x63, 0x5f, 0x74,
      0x65, 0x6d, 0x70, 0x6c, 0x61, 0x74, 0x65, 0x5f, 0x78, 0x78,
  };

  //"family_name_national_character"
  public static final byte[] family_name_national_character = {0x78, 0x1e,
      0x66, 0x61, 0x6d, 0x69, 0x6c, 0x79, 0x5f, 0x6e, 0x61, 0x6d,
      0x65, 0x5f, 0x6e, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x61, 0x6c, 0x5f, 0x63,
      0x68, 0x61, 0x72, 0x61, 0x63, 0x74, 0x65,
  };

  //"given_name_national_character"
  public static final byte[] given_name_national_character = {0x78, 0x1d,
      0x67, 0x69, 0x76, 0x65, 0x6e, 0x5f, 0x6e, 0x61, 0x6d, 0x65,
      0x5f, 0x6e, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x61, 0x6c, 0x5f, 0x63, 0x68,
      0x61, 0x72, 0x61, 0x63, 0x74, 0x65,
  };

  //"signature_usual_mark"
  public static final byte[] signature_usual_mark = {0x74,
      0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x5f, 0x75,
      0x73, 0x75, 0x61, 0x6c, 0x5f, 0x6d, 0x61, 0x72, 0x6b,
  };


  // COSE related constants
  public static final byte[] coseKeyKty = {1};
  public static final byte[] coseKeyEc2Crv = {0x20};
  public static final byte[] coseKeyEc2_X = {0x21};
  public static final byte[] coseKeyEc2_Y = {0x22};
  public static final short COSE_KEY_KTY_VAL_EC2 = 2;
  public static final short COSE_KEY_CRV_VAL_EC2_P256 = 1;
  public static final byte[] coseSignAlg = {1};
  public static final short MAX_COSE_KEY_SIZE = 128;
  public static final short MAX_SESSION_DATA_SIZE = 256;
  public static final short COSE_LABEL_ALG = 1;
  public static final short COSE_LABEL_X5CHAIN = 33;  // temporary identifier
  // From RFC 8152: Table 5: ECDSA Algorithm Values
  public static final short COSE_ALG_ECDSA_256 = -7;
  public static final short COSE_ALG_ECDSA_384 = -35;
  public static final short COSE_ALG_ECDSA_512 = -36;
  public static final short COSE_ALG_HMAC_256_256 = 5;

  // Structures and indexes used for the decoding
  public static final byte STRUCT_ROW_SIZE = 2;
  public static final byte STRUCT_KEY_OFFSET = 0;
  public static final byte STRUCT_VAL_OFFSET = 1;


  // Other constants
  public static final short MAX_SESSION_TRANSCRIPT_SIZE = 512;
  public static final byte EC_P256_COSE_KEY_SIZE = (2*(KeyBuilder.LENGTH_EC_FP_256/8) + 1) + 16;

  /**
   * Create Mdoc Credentials: Cbor Map {
   *   0 : CBOR Text String name,
   *    1 : CBOR Text String  docType,
   *     2 : CBOR uint numSigningKeys,
   *     3 : CBOR uint numUsesPerSigningKey,
   *     4 : CBOR uint signingKeyMinValidTimeMillis
   * }
   */


  public static final short[] STRUCT_MDOC_HAL_CMD = {
      KEY_ENC_DATA, CBOR_BINARY_STR,
      KEY_CERT, CBOR_BINARY_STR,
      KEY_HAL_CMD_DOC_SLOT, CBOR_UINT,
      KEY_TEST_CREDENTIAL, CBOR_UINT,
      KEY_CRED_CERT_CHALLENGE, CBOR_BINARY_STR,
      KEY_HAL_CMD_DOC_TYPE, CBOR_BINARY_STR,
      KEY_HAL_CMD_MDOC_NUM_SIGN_KEYS, CBOR_UINT,
      KEY_HAL_CMD_MDOC_USERS_PER_SIGN_KEY, CBOR_UINT,
      KEY_HAL_CMD_MDOC_VALID_TIME, CBOR_BINARY_STR,
      KEY_OPERATION, CBOR_UINT,
      KEY_CRED_DATA, CBOR_MAP,
      KEY_READER_ACCESS, CBOR_ARRAY,
      KEY_KEY_PARAMS, CBOR_MAP,
      KEY_ATTEST_KEY_PARAMS, CBOR_MAP,
      KEY_ATTEST_KEY_BLOB, CBOR_BINARY_STR,
  };
  // structures associated to main namespace elements
  public static final short[] STRUCT_SESSION_EST = {
      KEY_EREADER_KEY, CBOR_SEMANTIC_TAG,
      KEY_DEVICE_REQUEST, CBOR_BINARY_STR,
  };
  public static final short[] STRUCT_SESSION_DATA = {
      KEY_STATUS, CBOR_UINT,
      KEY_DEVICE_REQUEST, CBOR_BINARY_STR,
  };
  public static final short[] STRUCT_DEVICE_REQ = {
      KEY_VERSION, CBOR_TEXT_STR,
      KEY_DOC_REQUESTS, CBOR_ARRAY,
  };
  public static final short[] STRUCT_COSE_KEY = {
    KEY_COSE_KTY, CBOR_UINT, // TODO key can also be text string
    KEY_COSE_CRV, CBOR_UINT, // TODO key can also be text string
    KEY_COSE_X_COORD, CBOR_BINARY_STR,
    KEY_COSE_Y_COORD, CBOR_BINARY_STR, // TODO key can also be boolean
  };
  public static final short[] STRUCT_DEVICE_SIGNED = {
    KEY_NAME_SPACES, CBOR_SEMANTIC_TAG,
    KEY_DEVICE_AUTH, CBOR_NIL, // This is actually a map but for document being provisioned this
      // will always be nil
  };
  public static final short[] STRUCT_MDOC = {
    KEY_DOC_TYPE, CBOR_TEXT_STR,
      KEY_ISSUER_SIGNED, CBOR_MAP, //TODO in future we may want to decode this
    KEY_DEVICE_SIGNED, CBOR_MAP, //TODO in future we may want to decode this recursively. For
                                //  this we can use the key id to getStructure and recurse.
    KEY_ERRORS, CBOR_MAP,
  };
  public static final short[] STRUCT_MDOC_REQUEST = {
      KEY_ITEMS_REQUEST, CBOR_SEMANTIC_TAG,
      KEY_READER_AUTH, CBOR_ARRAY,
  };
  public static final short[] STRUCT_DEVICE_AUTH = {
      KEY_DEVICE_SIGNATURE, CBOR_ARRAY,
      KEY_DEVICE_MAC, CBOR_ARRAY,
  };
  public static final short[] STRUCT_ITEMS_REQUEST = {
      KEY_DOC_TYPE, CBOR_TEXT_STR,
      KEY_NAME_SPACES, CBOR_MAP,
      KEY_REQUEST_INFO, CBOR_MAP,
  };
  /**
   * CredentialData = {
   *        "docType": tstr,
   *        "digestIdMapping": DigestIdMapping,
   *        "issuerAuth" : IssuerAuth,
   *        "readerAccess" : ReaderAccess
   *      }
   *
   *      DigestIdMapping = {
   *        NameSpace => [ + IssuerSignedItemBytes ]
   *      }
   *
   *     ReaderAccess = [ * COSE_Key ]
   *
   *     DigestIdMapping = {
   *         NameSpace =&gt; [ + IssuerSignedItemBytes ]
   *     }
   *
   *     ; Defined in ISO 18013-5
   *     ;
   *     NameSpace = String
   *     DataElementIdentifier = String
   *     DigestID = uint
   *     IssuerAuth = COSE_Sign1 ; The payload is MobileSecurityObjectBytes
   *
   *     IssuerSignedItemBytes = #6.24(bstr .cbor IssuerSignedItem)
   *
   *     IssuerSignedItem = {
   *       "digestID" : uint,                           ; Digest ID for issuer data auth
   *       "random" : bstr,                             ; Random value for issuer data auth
   *       "elementIdentifier" : DataElementIdentifier, ; Data element identifier
   *       "elementValue" : NULL                        ; Placeholder for Data element value
   *     }
   */
  public static final short[] STRUCT_CRED_DATA = {
      KEY_DOC_TYPE, CBOR_TEXT_STR,
      KEY_ISSUER_NS, CBOR_MAP,
      KEY_ISSUER_AUTH, CBOR_ARRAY,
      KEY_READER_ACCESS, CBOR_ARRAY,
  };
  /**
   *     StaticAuthData = {
   *         "digestIdMapping": DigestIdMapping,
   *         "issuerAuth" : IssuerAuth
   *     }
   *
   *     DigestIdMapping = {
   *         NameSpace =&gt; [ + IssuerSignedItemBytes ]
   *     }
   *
   *     ; Defined in ISO 18013-5
   *     ;
   *     NameSpace = String
   *     DataElementIdentifier = String
   *     DigestID = uint
   *     IssuerAuth = COSE_Sign1 ; The payload is MobileSecurityObjectBytes
   *
   *     IssuerSignedItemBytes = #6.24(bstr .cbor IssuerSignedItem)
   *
   *     IssuerSignedItem = {
   *       "digestID" : uint,                           ; Digest ID for issuer data auth
   *       "random" : bstr,                             ; Random value for issuer data auth
   *       "elementIdentifier" : DataElementIdentifier, ; Data element identifier
   *       "elementValue" : NULL                        ; Placeholder for Data element value
   *     }
   */
  public static final short[] STRUCT_STATIC_AUTH_DATA = {
    KEY_DIGEST_MAPPING, CBOR_MAP,
    KEY_ISSUER_AUTH, CBOR_MAP, //Check whether this is an array
  };
  public static final short[] STRUCT_ISSUER_SIGNED_ITEM = {
      KEY_DIGEST_ID, CBOR_UINT,
      KEY_RANDOM, CBOR_BINARY_STR,
      KEY_ELEM_ID, CBOR_TEXT_STR,
      KEY_ELEM_VAL, CBOR_ANY,
  };
  public static final short[] STRUCT_MDL_DOCUMENT_DIGESTS = {
      KEY_MDL_NAMESPACE, CBOR_ARRAY,
  };
  public static final short[] STRUCT_ITEMS_REQUEST_NAMESPACES = {
      KEY_MDL_NAMESPACE, CBOR_MAP,
  };

  /*
  Generic_Headers = (
      ? 1 => int / tstr,  ; algorithm identifier
       ? 2 => [+label],    ; criticality
       ? 3 => tstr / int,  ; content type
       ? 4 => bstr,        ; key identifier
       ? 5 => bstr,        ; IV
       ? 6 => bstr,        ; Partial IV
       ? 7 => COSE_Signature / [+COSE_Signature] ; Counter signature
   */
  public static final short[] STRUCT_COSE_SIGN_1_HEADER = {
      KEY_COSE_SIGN_ALG, CBOR_TEXT_STR, // We are only interested in Algorithm.
      (short) 2, CBOR_ARRAY,
      (short) 3, CBOR_UINT, // TODO key can also be text string
      (short) 4, CBOR_BINARY_STR,
      (short) 5, CBOR_BINARY_STR,
      (short) 6, CBOR_BINARY_STR,
      (short) 7, CBOR_ARRAY, // TODO key can also be just one array or array of arrays
  };
  static final byte[] DEVICE_REQ_VERSION = {0x63, 0x31, 0x2e, 0x30};
  static final short MDL_ERR_NOT_FOUND = 10;
  private static final short MDL_DOCUMENT_REQ_ERROR = -2;
  private static final short MDL_ERR_READER_AUTH_FAILED= 10;


  // Returns structure for a given key
  public static short[] getStructure(short key){
    switch(key){
      case IND_SESSION_DATA:
        return STRUCT_SESSION_DATA;
      case IND_SESSION_ESTABLISHMENT:
        return STRUCT_SESSION_EST;
      case IND_STATIC_AUTH_DATA:
        return STRUCT_STATIC_AUTH_DATA;
      case IND_ISSUER_SIGNED_ITEM:
        return STRUCT_ISSUER_SIGNED_ITEM;
      case IND_CRED_DATA_DIGEST_MAPPING:
        return STRUCT_MDL_DOCUMENT_DIGESTS;
      case IND_MDOC_HAL_CMD:
        return STRUCT_MDOC_HAL_CMD;
      case KEY_EREADER_KEY:
        return STRUCT_COSE_KEY;
      case KEY_DEVICE_REQUEST:
        return STRUCT_DEVICE_REQ;
      case KEY_DEVICE_SIGNED:
        return STRUCT_DEVICE_SIGNED;
      case KEY_ITEMS_REQUEST:
        return STRUCT_ITEMS_REQUEST;
      case KEY_DOC_REQUESTS:
        return STRUCT_MDOC_REQUEST;
      case IND_MDOC:
        return STRUCT_MDOC;
      case KEY_DEVICE_AUTH:
        return STRUCT_DEVICE_AUTH;
      case KEY_CRED_DATA:
        return STRUCT_CRED_DATA;
      default:
        ISOException.throwIt(ISO7816.SW_UNKNOWN);
    }
    return null;
  }

  // Structures and functions to decode the incoming data

  // This is the entry for decoder.
//  public static short decodeStructure(short[] reqType, short[] retStructure, byte[] buffer,
//      short index, short length) {
//    CBORDecoder decoder = mDecoder.init(buffer, index, length);
//    return decodeStructure(decoder, reqType, retStructure);
//  }

  private static CBORDecoder mDecoder;
  private static CBORDecoder decoder(){
    if(mDecoder == null) {
      mDecoder = new CBORDecoder();
    }
    return mDecoder;
  }
  public static short  decodeStructure(short[] reqType, short[] retStructure, byte[] buf,
      short index, short length){
    decoder().init(buf,index, length);
    clearStructure(retStructure);
    byte[] buffer = decoder().getBuffer();
    short numElements = decoder().readMajorType(CBORBase.TYPE_MAP);
    if((short)(numElements * 2) > (short) reqType.length){
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
    while(numElements > 0 ){
      short rowIndex = getKey(reqType, decoder().getBuffer(), decoder().getCurrentOffset()); // returns matching row in structure
      // All keys are used only once in a request
      // TODO in the future this can be extended such that cardinality is part of the rule
      if(retStructure[rowIndex] != 0){
        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
      }
      short valType = reqType[(short)(rowIndex + MdlSpecifications.STRUCT_VAL_OFFSET)];
      short valStart = decoder().skipEntry(); // skip the key part
      assertValType(valType, buffer, valStart);
      short valEnd = decoder().skipEntry(); // skip the value
      short valLen = (short) ( valEnd - valStart);
      retStructure[rowIndex++] = valStart;
      retStructure[rowIndex] = valLen;
      numElements--;
    }
    return decoder().getCurrentOffset();
  }
  private static void clearStructure(short[] struct){
    byte len = (byte)struct.length;
    for( byte i = 0; i < len; i++){
      struct[i] = 0;
    }
  }
  private static short getKey(short[] struct, byte[] buf, short keyStart){
    byte index = 0;
    byte len = (byte) struct.length;
    while(index < len){
      if(MdlSpecifications.compareMain(struct[index], buf, keyStart)){
        return index;
      }else if(MdlSpecifications.compareDocNameSpaces(struct[index], buf, keyStart)){
        return index;
      }
      index = (byte)(index + MdlSpecifications.STRUCT_ROW_SIZE + MdlSpecifications.STRUCT_KEY_OFFSET);
    }
    ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    return -1;
  }
  public static short getNsElemKey(short nsKey, short[] nameSpace, byte[] buf, short keyStart) {
    for (byte i = 0; i < (short) nameSpace.length; i+=2) {
      if (compareElements(nsKey, nameSpace[i], buf, keyStart)) {
        return nameSpace[i];
      }
    }
    return -1;
  }
  private static short assertValType(short type, byte[] buf, short index){
    switch(type){
      case CBOR_SEMANTIC_TAG:
        if((short)(buf[index] & CBOR_MAJOR_TYPE_MASK) != CBOR_SEMANTIC_TAG  ||
                (short)(buf[index++] & CBOR_ADDITIONAL_MASK) != CBOR_UINT8_LENGTH ||
                (short)buf[index++] != CBOR_SEMANTIC_TAG_ENCODED_CBOR){
          ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        type = CBOR_BINARY_STR;
      case CBOR_BINARY_STR:
      case CBOR_TEXT_STR:
      case CBOR_MAP:
      case CBOR_ARRAY:
        if((buf[index] & CBOR_MAJOR_TYPE_MASK) != type){
          ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        break;
      case CBOR_UINT:
      case CBOR_NEG_INT:
        byte t = (byte) (buf[index] & CBOR_MAJOR_TYPE_MASK);
        if (t != CBOR_UINT && t != CBOR_NEG_INT){
          ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        break;
      case CBOR_NIL:
        if(CBOR_NIL != buf[index]){
          ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        break;
      case CBOR_BOOL:
        if(CBOR_TRUE != buf[index] && CBOR_FALSE != buf[index]){
          ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        break;
      case CBOR_ANY:
        break;
      default:
        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        break;
    }
    return index;
  }

// compare tables
  static boolean compareDocTypes(short keyId, byte[] buf, short keyStart, short len){
    byte[] str = null;
    switch(keyId){
      case KEY_MDL_DOC_TYPE:
        str = mdlDocType;
        break;
      default:
        break;
    }
    return (str != null) &&
        (Util.arrayCompare(buf, keyStart, str, (short)0, (short) str.length) ==0);
  }

  static boolean compareDocNameSpaces(short keyId, byte[] buf, short keyStart){
    byte[] str = getDocNameSpaceString(keyId);
    return (str != null) &&
        (Util.arrayCompare(buf, keyStart, str, (short)0, (short) str.length) ==0);
  }
  static byte[] getDocNameSpaceString(short keyId){
    byte[] str = null;
    switch(keyId){
      case KEY_MDL_NAMESPACE:
        str = mdlNameSpace;
        break;
      default:
        break;
    }
    return str;
  }
  public static short getNameSpacesKey(byte[] buf, short keyStart){
    for(byte i = 0; i < (short)NAMESPACES.length; i++) {
      if(compareDocNameSpaces(NAMESPACES[i], buf, keyStart)){
        return NAMESPACES[i];
      }
    }
    return -1;
  }

  static boolean compareElements(short nsKey, short elemKey, byte[] buf, short keyStart) {
    switch(nsKey){
      case KEY_MDL_NAMESPACE:
        return compareNameSpaceElements_Mdl(elemKey,buf,keyStart);
      default:
        break;
    }
    return false;
  }

  private static boolean compareNameSpaceElements_Mdl(short keyId, byte[] buf, short keyStart){
    byte[] str = getNameSpaceElements_Mdl(keyId);
    return compare(str, buf, keyStart);
  }
  static byte[] getNameSpaceElements_Mdl(short keyId){
    byte[] str = null;
    switch(keyId) {
      case KEY_ELEM_FAMILY_NAME:
        str = family_name;
        break;
      case KEY_ELEM_GIVEN_NAME:
        str = given_name;
        break;
      case KEY_ELEM_BIRTH_DATE:
        str = birth_date;
        break;
      case KEY_ELEM_ISSUE_DATE:
        str = issue_date;
        break;
      case KEY_ELEM_EXPIRY_DATE:
        str = expiry_date;
        break;
      case KEY_ELEM_ISSUING_COUNTRY:
        str = issuing_country;
        break;
      case KEY_ELEM_ISSUING_AUTHORITY:
        str = issuing_authority;
        break;
      case KEY_ELEM_DOCUMENT_NUMBER:
        str = document_number;
        break;
      case KEY_ELEM_PORTRAIT:
        str = portrait;
        break;
      case KEY_ELEM_DRIVING_PRIVILEGES:
        str = driving_privileges;
        break;
      case KEY_ELEM_UN_DISTINGUISHING_SIGN:
        str = un_distinguishing_sign;
        break;
      case KEY_ELEM_ADMINISTRATIVE_NUMBER:
        str = administrative_number;
        break;
      case KEY_ELEM_SEX:
        str = sex;
        break;
      case KEY_ELEM_HEIGHT:
        str = height;
        break;
      case KEY_ELEM_WEIGHT:
        str = weight;
        break;
      case KEY_ELEM_EYE_COLOUR:
        str = eye_colour;
        break;
      case KEY_ELEM_HAIR_COLOUR:
        str = hair_colour;
        break;
      case KEY_ELEM_BIRTH_PLACE:
        str = birth_place;
        break;
      case KEY_ELEM_RESIDENT_ADDRESS:
        str = resident_address;
        break;
      case KEY_ELEM_PORTRAIT_CAPTURE_DATE:
        str = portrait_capture_date;
        break;
      case KEY_ELEM_AGE_IN_YEARS:
        str = age_in_years;
        break;
      case KEY_ELEM_AGE_BIRTH_YEAR:
        str = age_birth_year;
        break;
      case KEY_ELEM_AGE_OVER_NN:
        str = age_over_NN;
        break;
      case KEY_ELEM_ISSUING_JURISDICTION:
        str = issuing_jurisdiction;
        break;
      case KEY_ELEM_NATIONALITY:
        str = nationality;
        break;
      case KEY_ELEM_RESIDENT_CITY:
        str = resident_city;
        break;
      case KEY_ELEM_RESIDENT_STATE:
        str = resident_state;
        break;
      case KEY_ELEM_RESIDENT_POSTAL_CODE:
        str = resident_postal_code;
        break;
      case KEY_ELEM_RESIDENT_COUNTRY:
        str = resident_country;
        break;
      case KEY_ELEM_BIOMETRIC_TEMPLATE_XX:
        str = biometric_template_xx;
        break;
      case KEY_ELEM_FAMILY_NAME_NATIONAL_CHARACTER:
        str = family_name_national_character;
        break;
      case KEY_ELEM_GIVEN_NAME_NATIONAL_CHARACTER:
        str = given_name_national_character;
        break;
      case KEY_ELEM_SIGNATURE_USUAL_MARK:
        str = signature_usual_mark;
        break;
      default:
        break;
    }
    return str;
  }
  // Main namespace elements mapping table.
  private static boolean compareMain(short keyId, byte[] buf, short keyStart){
    byte[] str = null;
    switch(keyId) {
      case KEY_READER_ACCESS:
        str = readerAccess;
        break;
      case KEY_EREADER_KEY:
        str = session_eReaderKey;
        break;
      case KEY_DEVICE_REQUEST:
        str = session_data;
        break;
      case KEY_STATUS:
        str = status;
        break;
      case KEY_VERSION:
        str = version;
        break;
      case KEY_DOC_REQUESTS:
        str = docRequests;
        break;
      case KEY_COSE_KTY:
        str = coseKeyKty;
        break;
      case KEY_COSE_CRV:
        str = coseKeyEc2Crv;
        break;
      case KEY_COSE_X_COORD:
        str = coseKeyEc2_X;
        break;
      case KEY_COSE_Y_COORD:
        str = coseKeyEc2_Y;
        break;
      case KEY_COSE_SIGN_ALG:
        str = coseSignAlg;
        break;
      case KEY_DOC_TYPE:
        str = docType;
        break;
      case KEY_ISSUER_SIGNED:
        str = issuerSigned;
        break;
      case KEY_DEVICE_SIGNED:
        str = deviceSigned;
        break;
      case KEY_ERRORS:
        str = errors;
        break;
      case KEY_NAME_SPACES:
        str = nameSpaces;
        break;
      case KEY_DEVICE_AUTH:
        str = deviceAuth;
        break;
      case KEY_DEVICE_SIGNATURE:
        str = deviceSignature;
        break;
      case KEY_DEVICE_MAC:
        str = deviceMac;
        break;
      case KEY_READER_AUTH:
        str = readerAuth;
        break;
      case KEY_ITEMS_REQUEST:
        str = itemsRequest;
        break;
      case KEY_REQUEST_INFO:
        str = requestInfo;
        break;
      case KEY_DIGEST_MAPPING:
        str = digestIdMapping;
        break;
      case KEY_ISSUER_NS:
        str = issuerNameSpaces;
        break;
      case KEY_DIGEST_ID:
        str = digestID;
        break;
      case KEY_RANDOM:
        str = random;
        break;
      case KEY_ELEM_ID:
        str = elementIdentifier;
        break;
      case KEY_ELEM_VAL:
        str = elementValue;
        break;
      case KEY_ISSUER_AUTH:
        str = issuerAuth;
        break;
      default:
        break;
    }
    return compare(str, buf, keyStart);
  }

  private static boolean compare(byte[] key, byte[] buf, short start){
    return (key != null) &&
        (Util.arrayCompare(buf, start, key, (short)0, (short) key.length) ==0);
  }

  public static short[] getNsStructure(short i) {
    switch (i){
      case KEY_MDL_NAMESPACE:
        return STRUCT_MDL_NAME_SPACE_ELEMENTS;
      default:
        return null;
    }
  }

  public static short decodeTaggedStructure(short[] struct, short[] temp, byte[] buf, short start,
      short len) {
    short n = Util.getShort(buf, start);
    if(Util.getShort(buf, start) != (short)0xD818){
      return -1;
    }
    start += 2;
    decoder().init(buf, start, len);
    len = decoder().readMajorType(CBORBase.TYPE_BYTE_STRING);
    return decodeStructure(struct, temp,buf, decoder().getCurrentOffset(),len);
  }

  public static final short[] STRUCT_DOC_REQUEST_NAMESPACES = {
    KEY_MDL_NAMESPACE, CBOR_MAP,
  };
  public static final short[] STRUCT_MDL_NAME_SPACE_ITEM_REQUESTS_DEVICE_ELEMENTS = {
      KEY_ELEM_FAMILY_NAME,CBOR_BOOL,
      KEY_ELEM_GIVEN_NAME,CBOR_BOOL,
      KEY_ELEM_BIRTH_DATE,CBOR_BOOL,
      KEY_ELEM_ISSUE_DATE,CBOR_BOOL,
      KEY_ELEM_EXPIRY_DATE,CBOR_BOOL,
      KEY_ELEM_ISSUING_COUNTRY,CBOR_BOOL,
      KEY_ELEM_ISSUING_AUTHORITY,CBOR_BOOL,
      KEY_ELEM_DOCUMENT_NUMBER,CBOR_BOOL,
      KEY_ELEM_PORTRAIT,CBOR_BOOL,
      KEY_ELEM_DRIVING_PRIVILEGES,CBOR_BOOL,
      KEY_ELEM_UN_DISTINGUISHING_SIGN,CBOR_BOOL,
      KEY_ELEM_ADMINISTRATIVE_NUMBER,CBOR_BOOL,
      KEY_ELEM_SEX,CBOR_BOOL,
      KEY_ELEM_HEIGHT,CBOR_BOOL,
      KEY_ELEM_WEIGHT,CBOR_BOOL,
      KEY_ELEM_EYE_COLOUR,CBOR_BOOL,
      KEY_ELEM_HAIR_COLOUR,CBOR_BOOL,
      KEY_ELEM_BIRTH_PLACE,CBOR_BOOL,
      KEY_ELEM_RESIDENT_ADDRESS,CBOR_BOOL,
      KEY_ELEM_PORTRAIT_CAPTURE_DATE,CBOR_BOOL,
      KEY_ELEM_AGE_IN_YEARS,CBOR_BOOL,
      KEY_ELEM_AGE_BIRTH_YEAR,CBOR_BOOL,
      KEY_ELEM_AGE_OVER_NN,CBOR_BOOL,
      KEY_ELEM_ISSUING_JURISDICTION,CBOR_BOOL,
      KEY_ELEM_NATIONALITY,CBOR_BOOL,
      KEY_ELEM_RESIDENT_CITY,CBOR_BOOL,
      KEY_ELEM_RESIDENT_STATE,CBOR_BOOL,
      KEY_ELEM_RESIDENT_POSTAL_CODE,CBOR_BOOL,
      KEY_ELEM_RESIDENT_COUNTRY,CBOR_BOOL,
      KEY_ELEM_BIOMETRIC_TEMPLATE_XX,CBOR_BOOL,
      KEY_ELEM_FAMILY_NAME_NATIONAL_CHARACTER,CBOR_BOOL,
      KEY_ELEM_GIVEN_NAME_NATIONAL_CHARACTER,CBOR_BOOL,
      KEY_ELEM_SIGNATURE_USUAL_MARK,CBOR_BOOL,
  };

}
