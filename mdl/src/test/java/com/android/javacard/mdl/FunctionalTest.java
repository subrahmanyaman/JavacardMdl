package com.android.javacard.mdl;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import co.nstant.in.cbor.CborBuilder;
import co.nstant.in.cbor.builder.MapBuilder;
import co.nstant.in.cbor.model.Array;
import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.Map;
import co.nstant.in.cbor.model.UnicodeString;
import co.nstant.in.cbor.model.UnsignedInteger;
import com.android.javacard.mdl.jcardsim.SEProvider;
import com.android.javacard.mdl.nfc.DataRetrievalAddress;
import com.android.javacard.mdl.nfc.TestUtil;
import com.android.javacard.mdl.nfc.VerificationHelper;
import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECPoint;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import javacard.framework.AID;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.ECPublicKey;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
//import org.jetbrains.annotations.Nullable;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemObjectGenerator;
import org.bouncycastle.util.io.pem.PemWriter;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(AndroidJUnit4.class)
public class FunctionalTest {
  private static final byte[] kEcAttestPrivateKey = {
      (byte) (0x21), (byte) (0xE0), (byte) (0x86),
      (byte) (0x43), (byte) (0x2A), (byte) (0x15),
      (byte) (0x19), (byte) (0x84), (byte) (0x59),
      (byte) (0xCF), (byte) (0x36), (byte) (0x3A),
      (byte) (0x50), (byte) (0xFC), (byte) (0x14),
      (byte) (0xC9), (byte) (0xDA), (byte) (0xAD),
      (byte) (0xF9), (byte) (0x35), (byte) (0xF5),
      (byte) (0x27), (byte) (0xC2), (byte) (0xDF),
      (byte) (0xD7), (byte) (0x1E), (byte) (0x4D),
      (byte) (0x6D), (byte) (0xBC), (byte) (0x42),
      (byte) (0xE5), (byte) (0x44),
  };
  
  private static final byte[] kEcAttestKey = {
      (byte) (0x30), (byte) (0x77), (byte) (0x02), (byte) (0x01), (byte) (0x01), (byte) (0x04),
      (byte) (0x20), (byte) (0x21), (byte) (0xe0), (byte) (0x86), (byte) (0x43), (byte) (0x2a),
      (byte) (0x15), (byte) (0x19), (byte) (0x84), (byte) (0x59), (byte) (0xcf), (byte) (0x36),
      (byte) (0x3a), (byte) (0x50), (byte) (0xfc), (byte) (0x14), (byte) (0xc9), (byte) (0xda),
      (byte) (0xad), (byte) (0xf9), (byte) (0x35), (byte) (0xf5), (byte) (0x27), (byte) (0xc2),
      (byte) (0xdf), (byte) (0xd7), (byte) (0x1e), (byte) (0x4d), (byte) (0x6d), (byte) (0xbc),
      (byte) (0x42), (byte) (0xe5), (byte) (0x44), (byte) (0xa0), (byte) (0x0a), (byte) (0x06),
      (byte) (0x08), (byte) (0x2a), (byte) (0x86), (byte) (0x48), (byte) (0xce), (byte) (0x3d),
      (byte) (0x03), (byte) (0x01), (byte) (0x07), (byte) (0xa1), (byte) (0x44), (byte) (0x03),
      (byte) (0x42), (byte) (0x00), (byte) (0x04), (byte) (0xeb), (byte) (0x9e), (byte) (0x79),
      (byte) (0xf8), (byte) (0x42), (byte) (0x63), (byte) (0x59), (byte) (0xac), (byte) (0xcb),
      (byte) (0x2a), (byte) (0x91), (byte) (0x4c), (byte) (0x89), (byte) (0x86), (byte) (0xcc),
      (byte) (0x70), (byte) (0xad), (byte) (0x90), (byte) (0x66), (byte) (0x93), (byte) (0x82),
      (byte) (0xa9), (byte) (0x73), (byte) (0x26), (byte) (0x13), (byte) (0xfe), (byte) (0xac),
      (byte) (0xcb), (byte) (0xf8), (byte) (0x21), (byte) (0x27), (byte) (0x4c), (byte) (0x21),
      (byte) (0x74), (byte) (0x97), (byte) (0x4a), (byte) (0x2a), (byte) (0xfe), (byte) (0xa5),
      (byte) (0xb9), (byte) (0x4d), (byte) (0x7f), (byte) (0x66), (byte) (0xd4), (byte) (0xe0),
      (byte) (0x65), (byte) (0x10), (byte) (0x66), (byte) (0x35), (byte) (0xbc), (byte) (0x53),
      (byte) (0xb7), (byte) (0xa0), (byte) (0xa3), (byte) (0xa6), (byte) (0x71), (byte) (0x58),
      (byte) (0x3e), (byte) (0xdb), (byte) (0x3e), (byte) (0x11), (byte) (0xae), (byte) (0x10),
      (byte) (0x14),
  };

  private static final byte[] kEcAttestCert= {
      (byte) (0x30), (byte) (0x82), (byte) (0x02), (byte) (0x78),
      (byte) (0x30), (byte) (0x82), (byte) (0x02), (byte) (0x1e),
      (byte) (0xa0), (byte) (0x03), (byte) (0x02), (byte) (0x01),
      (byte) (0x02), (byte) (0x02), (byte) (0x02), (byte) (0x10),
      (byte) (0x01), (byte) (0x30), (byte) (0x0a), (byte) (0x06),
      (byte) (0x08), (byte) (0x2a), (byte) (0x86), (byte) (0x48),
      (byte) (0xce), (byte) (0x3d), (byte) (0x04), (byte) (0x03),
      (byte) (0x02), (byte) (0x30), (byte) (0x81), (byte) (0x98),
      (byte) (0x31), (byte) (0x0b), (byte) (0x30), (byte) (0x09),
      (byte) (0x06), (byte) (0x03), (byte) (0x55), (byte) (0x04),
      (byte) (0x06), (byte) (0x13), (byte) (0x02), (byte) (0x55),
      (byte) (0x53), (byte) (0x31), (byte) (0x13), (byte) (0x30),
      (byte) (0x11), (byte) (0x06), (byte) (0x03), (byte) (0x55),
      (byte) (0x04), (byte) (0x08), (byte) (0x0c), (byte) (0x0a),
      (byte) (0x43), (byte) (0x61), (byte) (0x6c), (byte) (0x69),
      (byte) (0x66), (byte) (0x6f), (byte) (0x72), (byte) (0x6e),
      (byte) (0x69), (byte) (0x61), (byte) (0x31), (byte) (0x16),
      (byte) (0x30), (byte) (0x14), (byte) (0x06), (byte) (0x03),
      (byte) (0x55), (byte) (0x04), (byte) (0x07), (byte) (0x0c),
      (byte) (0x0d), (byte) (0x4d), (byte) (0x6f), (byte) (0x75),
      (byte) (0x6e), (byte) (0x74), (byte) (0x61), (byte) (0x69),
      (byte) (0x6e), (byte) (0x20), (byte) (0x56), (byte) (0x69),
      (byte) (0x65), (byte) (0x77), (byte) (0x31), (byte) (0x15),
      (byte) (0x30), (byte) (0x13), (byte) (0x06), (byte) (0x03),
      (byte) (0x55), (byte) (0x04), (byte) (0x0a), (byte) (0x0c),
      (byte) (0x0c), (byte) (0x47), (byte) (0x6f), (byte) (0x6f),
      (byte) (0x67), (byte) (0x6c), (byte) (0x65), (byte) (0x2c),
      (byte) (0x20), (byte) (0x49), (byte) (0x6e), (byte) (0x63),
      (byte) (0x2e), (byte) (0x31), (byte) (0x10), (byte) (0x30),
      (byte) (0x0e), (byte) (0x06), (byte) (0x03), (byte) (0x55),
      (byte) (0x04), (byte) (0x0b), (byte) (0x0c), (byte) (0x07),
      (byte) (0x41), (byte) (0x6e), (byte) (0x64), (byte) (0x72),
      (byte) (0x6f), (byte) (0x69), (byte) (0x64), (byte) (0x31),
      (byte) (0x33), (byte) (0x30), (byte) (0x31), (byte) (0x06),
      (byte) (0x03), (byte) (0x55), (byte) (0x04), (byte) (0x03),
      (byte) (0x0c), (byte) (0x2a), (byte) (0x41), (byte) (0x6e),
      (byte) (0x64), (byte) (0x72), (byte) (0x6f), (byte) (0x69),
      (byte) (0x64), (byte) (0x20), (byte) (0x4b), (byte) (0x65),
      (byte) (0x79), (byte) (0x73), (byte) (0x74), (byte) (0x6f),
      (byte) (0x72), (byte) (0x65), (byte) (0x20), (byte) (0x53),
      (byte) (0x6f), (byte) (0x66), (byte) (0x74), (byte) (0x77),
      (byte) (0x61), (byte) (0x72), (byte) (0x65), (byte) (0x20),
      (byte) (0x41), (byte) (0x74), (byte) (0x74), (byte) (0x65),
      (byte) (0x73), (byte) (0x74), (byte) (0x61), (byte) (0x74),
      (byte) (0x69), (byte) (0x6f), (byte) (0x6e), (byte) (0x20),
      (byte) (0x52), (byte) (0x6f), (byte) (0x6f), (byte) (0x74),
      (byte) (0x30), (byte) (0x1e), (byte) (0x17), (byte) (0x0d),
      (byte) (0x31), (byte) (0x36), (byte) (0x30), (byte) (0x31),
      (byte) (0x31), (byte) (0x31), (byte) (0x30), (byte) (0x30),
      (byte) (0x34), (byte) (0x36), (byte) (0x30), (byte) (0x39),
      (byte) (0x5a), (byte) (0x17), (byte) (0x0d), (byte) (0x32),
      (byte) (0x36), (byte) (0x30), (byte) (0x31), (byte) (0x30),
      (byte) (0x38), (byte) (0x30), (byte) (0x30), (byte) (0x34),
      (byte) (0x36), (byte) (0x30), (byte) (0x39), (byte) (0x5a),
      (byte) (0x30), (byte) (0x81), (byte) (0x88), (byte) (0x31),
      (byte) (0x0b), (byte) (0x30), (byte) (0x09), (byte) (0x06),
      (byte) (0x03), (byte) (0x55), (byte) (0x04), (byte) (0x06),
      (byte) (0x13), (byte) (0x02), (byte) (0x55), (byte) (0x53),
      (byte) (0x31), (byte) (0x13), (byte) (0x30), (byte) (0x11),
      (byte) (0x06), (byte) (0x03), (byte) (0x55), (byte) (0x04),
      (byte) (0x08), (byte) (0x0c), (byte) (0x0a), (byte) (0x43),
      (byte) (0x61), (byte) (0x6c), (byte) (0x69), (byte) (0x66),
      (byte) (0x6f), (byte) (0x72), (byte) (0x6e), (byte) (0x69),
      (byte) (0x61), (byte) (0x31), (byte) (0x15), (byte) (0x30),
      (byte) (0x13), (byte) (0x06), (byte) (0x03), (byte) (0x55),
      (byte) (0x04), (byte) (0x0a), (byte) (0x0c), (byte) (0x0c),
      (byte) (0x47), (byte) (0x6f), (byte) (0x6f), (byte) (0x67),
      (byte) (0x6c), (byte) (0x65), (byte) (0x2c), (byte) (0x20),
      (byte) (0x49), (byte) (0x6e), (byte) (0x63), (byte) (0x2e),
      (byte) (0x31), (byte) (0x10), (byte) (0x30), (byte) (0x0e),
      (byte) (0x06), (byte) (0x03), (byte) (0x55), (byte) (0x04),
      (byte) (0x0b), (byte) (0x0c), (byte) (0x07), (byte) (0x41),
      (byte) (0x6e), (byte) (0x64), (byte) (0x72), (byte) (0x6f),
      (byte) (0x69), (byte) (0x64), (byte) (0x31), (byte) (0x3b),
      (byte) (0x30), (byte) (0x39), (byte) (0x06), (byte) (0x03),
      (byte) (0x55), (byte) (0x04), (byte) (0x03), (byte) (0x0c),
      (byte) (0x32), (byte) (0x41), (byte) (0x6e), (byte) (0x64),
      (byte) (0x72), (byte) (0x6f), (byte) (0x69), (byte) (0x64),
      (byte) (0x20), (byte) (0x4b), (byte) (0x65), (byte) (0x79),
      (byte) (0x73), (byte) (0x74), (byte) (0x6f), (byte) (0x72),
      (byte) (0x65), (byte) (0x20), (byte) (0x53), (byte) (0x6f),
      (byte) (0x66), (byte) (0x74), (byte) (0x77), (byte) (0x61),
      (byte) (0x72), (byte) (0x65), (byte) (0x20), (byte) (0x41),
      (byte) (0x74), (byte) (0x74), (byte) (0x65), (byte) (0x73),
      (byte) (0x74), (byte) (0x61), (byte) (0x74), (byte) (0x69),
      (byte) (0x6f), (byte) (0x6e), (byte) (0x20), (byte) (0x49),
      (byte) (0x6e), (byte) (0x74), (byte) (0x65), (byte) (0x72),
      (byte) (0x6d), (byte) (0x65), (byte) (0x64), (byte) (0x69),
      (byte) (0x61), (byte) (0x74), (byte) (0x65), (byte) (0x30),
      (byte) (0x59), (byte) (0x30), (byte) (0x13), (byte) (0x06),
      (byte) (0x07), (byte) (0x2a), (byte) (0x86), (byte) (0x48),
      (byte) (0xce), (byte) (0x3d), (byte) (0x02), (byte) (0x01),
      (byte) (0x06), (byte) (0x08), (byte) (0x2a), (byte) (0x86),
      (byte) (0x48), (byte) (0xce), (byte) (0x3d), (byte) (0x03),
      (byte) (0x01), (byte) (0x07), (byte) (0x03), (byte) (0x42),
      (byte) (0x00), (byte) (0x04), (byte) (0xeb), (byte) (0x9e),
      (byte) (0x79), (byte) (0xf8), (byte) (0x42), (byte) (0x63),
      (byte) (0x59), (byte) (0xac), (byte) (0xcb), (byte) (0x2a),
      (byte) (0x91), (byte) (0x4c), (byte) (0x89), (byte) (0x86),
      (byte) (0xcc), (byte) (0x70), (byte) (0xad), (byte) (0x90),
      (byte) (0x66), (byte) (0x93), (byte) (0x82), (byte) (0xa9),
      (byte) (0x73), (byte) (0x26), (byte) (0x13), (byte) (0xfe),
      (byte) (0xac), (byte) (0xcb), (byte) (0xf8), (byte) (0x21),
      (byte) (0x27), (byte) (0x4c), (byte) (0x21), (byte) (0x74),
      (byte) (0x97), (byte) (0x4a), (byte) (0x2a), (byte) (0xfe),
      (byte) (0xa5), (byte) (0xb9), (byte) (0x4d), (byte) (0x7f),
      (byte) (0x66), (byte) (0xd4), (byte) (0xe0), (byte) (0x65),
      (byte) (0x10), (byte) (0x66), (byte) (0x35), (byte) (0xbc),
      (byte) (0x53), (byte) (0xb7), (byte) (0xa0), (byte) (0xa3),
      (byte) (0xa6), (byte) (0x71), (byte) (0x58), (byte) (0x3e),
      (byte) (0xdb), (byte) (0x3e), (byte) (0x11), (byte) (0xae),
      (byte) (0x10), (byte) (0x14), (byte) (0xa3), (byte) (0x66),
      (byte) (0x30), (byte) (0x64), (byte) (0x30), (byte) (0x1d),
      (byte) (0x06), (byte) (0x03), (byte) (0x55), (byte) (0x1d),
      (byte) (0x0e), (byte) (0x04), (byte) (0x16), (byte) (0x04),
      (byte) (0x14), (byte) (0x3f), (byte) (0xfc), (byte) (0xac),
      (byte) (0xd6), (byte) (0x1a), (byte) (0xb1), (byte) (0x3a),
      (byte) (0x9e), (byte) (0x81), (byte) (0x20), (byte) (0xb8),
      (byte) (0xd5), (byte) (0x25), (byte) (0x1c), (byte) (0xc5),
      (byte) (0x65), (byte) (0xbb), (byte) (0x1e), (byte) (0x91),
      (byte) (0xa9), (byte) (0x30), (byte) (0x1f), (byte) (0x06),
      (byte) (0x03), (byte) (0x55), (byte) (0x1d), (byte) (0x23),
      (byte) (0x04), (byte) (0x18), (byte) (0x30), (byte) (0x16),
      (byte) (0x80), (byte) (0x14), (byte) (0xc8), (byte) (0xad),
      (byte) (0xe9), (byte) (0x77), (byte) (0x4c), (byte) (0x45),
      (byte) (0xc3), (byte) (0xa3), (byte) (0xcf), (byte) (0x0d),
      (byte) (0x16), (byte) (0x10), (byte) (0xe4), (byte) (0x79),
      (byte) (0x43), (byte) (0x3a), (byte) (0x21), (byte) (0x5a),
      (byte) (0x30), (byte) (0xcf), (byte) (0x30), (byte) (0x12),
      (byte) (0x06), (byte) (0x03), (byte) (0x55), (byte) (0x1d),
      (byte) (0x13), (byte) (0x01), (byte) (0x01), (byte) (0xff),
      (byte) (0x04), (byte) (0x08), (byte) (0x30), (byte) (0x06),
      (byte) (0x01), (byte) (0x01), (byte) (0xff), (byte) (0x02),
      (byte) (0x01), (byte) (0x00), (byte) (0x30), (byte) (0x0e),
      (byte) (0x06), (byte) (0x03), (byte) (0x55), (byte) (0x1d),
      (byte) (0x0f), (byte) (0x01), (byte) (0x01), (byte) (0xff),
      (byte) (0x04), (byte) (0x04), (byte) (0x03), (byte) (0x02),
      (byte) (0x02), (byte) (0x84), (byte) (0x30), (byte) (0x0a),
      (byte) (0x06), (byte) (0x08), (byte) (0x2a), (byte) (0x86),
      (byte) (0x48), (byte) (0xce), (byte) (0x3d), (byte) (0x04),
      (byte) (0x03), (byte) (0x02), (byte) (0x03), (byte) (0x48),
      (byte) (0x00), (byte) (0x30), (byte) (0x45), (byte) (0x02),
      (byte) (0x20), (byte) (0x4b), (byte) (0x8a), (byte) (0x9b),
      (byte) (0x7b), (byte) (0xee), (byte) (0x82), (byte) (0xbc),
      (byte) (0xc0), (byte) (0x33), (byte) (0x87), (byte) (0xae),
      (byte) (0x2f), (byte) (0xc0), (byte) (0x89), (byte) (0x98),
      (byte) (0xb4), (byte) (0xdd), (byte) (0xc3), (byte) (0x8d),
      (byte) (0xab), (byte) (0x27), (byte) (0x2a), (byte) (0x45),
      (byte) (0x9f), (byte) (0x69), (byte) (0x0c), (byte) (0xc7),
      (byte) (0xc3), (byte) (0x92), (byte) (0xd4), (byte) (0x0f),
      (byte) (0x8e), (byte) (0x02), (byte) (0x21), (byte) (0x00),
      (byte) (0xee), (byte) (0xda), (byte) (0x01), (byte) (0x5d),
      (byte) (0xb6), (byte) (0xf4), (byte) (0x32), (byte) (0xe9),
      (byte) (0xd4), (byte) (0x84), (byte) (0x3b), (byte) (0x62),
      (byte) (0x4c), (byte) (0x94), (byte) (0x04), (byte) (0xef),
      (byte) (0x3a), (byte) (0x7c), (byte) (0xcc), (byte) (0xbd),
      (byte) (0x5e), (byte) (0xfb), (byte) (0x22), (byte) (0xbb),
      (byte) (0xe7), (byte) (0xfe), (byte) (0xb9), (byte) (0x77),
      (byte) (0x3f), (byte) (0x59), (byte) (0x3f), (byte) (0xfb),
  };

  private static final byte[] kEcAttestRootCert = {
    (byte) (0x30), (byte) (0x82), (byte) (0x02), (byte) (0x8b),
          (byte) (0x30), (byte) (0x82), (byte) (0x02), (byte) (0x32),
    (byte) (0xa0), (byte) (0x03), (byte) (0x02), (byte) (0x01),
          (byte) (0x02), (byte) (0x02), (byte) (0x09), (byte) (0x00),
    (byte) (0xa2), (byte) (0x05), (byte) (0x9e), (byte) (0xd1),
          (byte) (0x0e), (byte) (0x43), (byte) (0x5b), (byte) (0x57),
    (byte) (0x30), (byte) (0x0a), (byte) (0x06), (byte) (0x08),
          (byte) (0x2a), (byte) (0x86), (byte) (0x48), (byte) (0xce),
    (byte) (0x3d), (byte) (0x04), (byte) (0x03), (byte) (0x02),
          (byte) (0x30), (byte) (0x81), (byte) (0x98), (byte) (0x31),
    (byte) (0x0b), (byte) (0x30), (byte) (0x09), (byte) (0x06),
          (byte) (0x03), (byte) (0x55), (byte) (0x04), (byte) (0x06),
    (byte) (0x13), (byte) (0x02), (byte) (0x55), (byte) (0x53),
          (byte) (0x31), (byte) (0x13), (byte) (0x30), (byte) (0x11),
    (byte) (0x06), (byte) (0x03), (byte) (0x55), (byte) (0x04),
          (byte) (0x08), (byte) (0x0c), (byte) (0x0a), (byte) (0x43),
    (byte) (0x61), (byte) (0x6c), (byte) (0x69), (byte) (0x66),
          (byte) (0x6f), (byte) (0x72), (byte) (0x6e), (byte) (0x69),
    (byte) (0x61), (byte) (0x31), (byte) (0x16), (byte) (0x30),
          (byte) (0x14), (byte) (0x06), (byte) (0x03), (byte) (0x55),
    (byte) (0x04), (byte) (0x07), (byte) (0x0c), (byte) (0x0d),
          (byte) (0x4d), (byte) (0x6f), (byte) (0x75), (byte) (0x6e),
    (byte) (0x74), (byte) (0x61), (byte) (0x69), (byte) (0x6e),
          (byte) (0x20), (byte) (0x56), (byte) (0x69), (byte) (0x65),
    (byte) (0x77), (byte) (0x31), (byte) (0x15), (byte) (0x30),
          (byte) (0x13), (byte) (0x06), (byte) (0x03), (byte) (0x55),
    (byte) (0x04), (byte) (0x0a), (byte) (0x0c), (byte) (0x0c),
          (byte) (0x47), (byte) (0x6f), (byte) (0x6f), (byte) (0x67),
    (byte) (0x6c), (byte) (0x65), (byte) (0x2c), (byte) (0x20),
          (byte) (0x49), (byte) (0x6e), (byte) (0x63), (byte) (0x2e),
    (byte) (0x31), (byte) (0x10), (byte) (0x30), (byte) (0x0e),
          (byte) (0x06), (byte) (0x03), (byte) (0x55), (byte) (0x04),
    (byte) (0x0b), (byte) (0x0c), (byte) (0x07), (byte) (0x41),
          (byte) (0x6e), (byte) (0x64), (byte) (0x72), (byte) (0x6f),
    (byte) (0x69), (byte) (0x64), (byte) (0x31), (byte) (0x33),
          (byte) (0x30), (byte) (0x31), (byte) (0x06), (byte) (0x03),
    (byte) (0x55), (byte) (0x04), (byte) (0x03), (byte) (0x0c),
          (byte) (0x2a), (byte) (0x41), (byte) (0x6e), (byte) (0x64),
    (byte) (0x72), (byte) (0x6f), (byte) (0x69), (byte) (0x64),
          (byte) (0x20), (byte) (0x4b), (byte) (0x65), (byte) (0x79),
    (byte) (0x73), (byte) (0x74), (byte) (0x6f), (byte) (0x72),
          (byte) (0x65), (byte) (0x20), (byte) (0x53), (byte) (0x6f),
    (byte) (0x66), (byte) (0x74), (byte) (0x77), (byte) (0x61),
          (byte) (0x72), (byte) (0x65), (byte) (0x20), (byte) (0x41),
    (byte) (0x74), (byte) (0x74), (byte) (0x65), (byte) (0x73),
          (byte) (0x74), (byte) (0x61), (byte) (0x74), (byte) (0x69),
    (byte) (0x6f), (byte) (0x6e), (byte) (0x20), (byte) (0x52),
          (byte) (0x6f), (byte) (0x6f), (byte) (0x74), (byte) (0x30),
    (byte) (0x1e), (byte) (0x17), (byte) (0x0d), (byte) (0x31),
          (byte) (0x36), (byte) (0x30), (byte) (0x31), (byte) (0x31),
    (byte) (0x31), (byte) (0x30), (byte) (0x30), (byte) (0x34),
          (byte) (0x33), (byte) (0x35), (byte) (0x30), (byte) (0x5a),
    (byte) (0x17), (byte) (0x0d), (byte) (0x33), (byte) (0x36),
          (byte) (0x30), (byte) (0x31), (byte) (0x30), (byte) (0x36),
    (byte) (0x30), (byte) (0x30), (byte) (0x34), (byte) (0x33),
          (byte) (0x35), (byte) (0x30), (byte) (0x5a), (byte) (0x30),
    (byte) (0x81), (byte) (0x98), (byte) (0x31), (byte) (0x0b),
          (byte) (0x30), (byte) (0x09), (byte) (0x06), (byte) (0x03),
    (byte) (0x55), (byte) (0x04), (byte) (0x06), (byte) (0x13),
          (byte) (0x02), (byte) (0x55), (byte) (0x53), (byte) (0x31),
    (byte) (0x13), (byte) (0x30), (byte) (0x11), (byte) (0x06),
          (byte) (0x03), (byte) (0x55), (byte) (0x04), (byte) (0x08),
    (byte) (0x0c), (byte) (0x0a), (byte) (0x43), (byte) (0x61),
          (byte) (0x6c), (byte) (0x69), (byte) (0x66), (byte) (0x6f),
    (byte) (0x72), (byte) (0x6e), (byte) (0x69), (byte) (0x61),
          (byte) (0x31), (byte) (0x16), (byte) (0x30), (byte) (0x14),
    (byte) (0x06), (byte) (0x03), (byte) (0x55), (byte) (0x04),
          (byte) (0x07), (byte) (0x0c), (byte) (0x0d), (byte) (0x4d),
    (byte) (0x6f), (byte) (0x75), (byte) (0x6e), (byte) (0x74),
          (byte) (0x61), (byte) (0x69), (byte) (0x6e), (byte) (0x20),
    (byte) (0x56), (byte) (0x69), (byte) (0x65), (byte) (0x77),
          (byte) (0x31), (byte) (0x15), (byte) (0x30), (byte) (0x13),
    (byte) (0x06), (byte) (0x03), (byte) (0x55), (byte) (0x04),
          (byte) (0x0a), (byte) (0x0c), (byte) (0x0c), (byte) (0x47),
    (byte) (0x6f), (byte) (0x6f), (byte) (0x67), (byte) (0x6c),
          (byte) (0x65), (byte) (0x2c), (byte) (0x20), (byte) (0x49),
    (byte) (0x6e), (byte) (0x63), (byte) (0x2e), (byte) (0x31),
          (byte) (0x10), (byte) (0x30), (byte) (0x0e), (byte) (0x06),
    (byte) (0x03), (byte) (0x55), (byte) (0x04), (byte) (0x0b),
          (byte) (0x0c), (byte) (0x07), (byte) (0x41), (byte) (0x6e),
    (byte) (0x64), (byte) (0x72), (byte) (0x6f), (byte) (0x69),
          (byte) (0x64), (byte) (0x31), (byte) (0x33), (byte) (0x30),
    (byte) (0x31), (byte) (0x06), (byte) (0x03), (byte) (0x55),
          (byte) (0x04), (byte) (0x03), (byte) (0x0c), (byte) (0x2a),
    (byte) (0x41), (byte) (0x6e), (byte) (0x64), (byte) (0x72),
          (byte) (0x6f), (byte) (0x69), (byte) (0x64), (byte) (0x20),
    (byte) (0x4b), (byte) (0x65), (byte) (0x79), (byte) (0x73),
          (byte) (0x74), (byte) (0x6f), (byte) (0x72), (byte) (0x65),
    (byte) (0x20), (byte) (0x53), (byte) (0x6f), (byte) (0x66),
          (byte) (0x74), (byte) (0x77), (byte) (0x61), (byte) (0x72),
    (byte) (0x65), (byte) (0x20), (byte) (0x41), (byte) (0x74),
          (byte) (0x74), (byte) (0x65), (byte) (0x73), (byte) (0x74),
    (byte) (0x61), (byte) (0x74), (byte) (0x69), (byte) (0x6f),
          (byte) (0x6e), (byte) (0x20), (byte) (0x52), (byte) (0x6f),
    (byte) (0x6f), (byte) (0x74), (byte) (0x30), (byte) (0x59),
          (byte) (0x30), (byte) (0x13), (byte) (0x06), (byte) (0x07),
    (byte) (0x2a), (byte) (0x86), (byte) (0x48), (byte) (0xce),
          (byte) (0x3d), (byte) (0x02), (byte) (0x01), (byte) (0x06),
    (byte) (0x08), (byte) (0x2a), (byte) (0x86), (byte) (0x48),
          (byte) (0xce), (byte) (0x3d), (byte) (0x03), (byte) (0x01),
    (byte) (0x07), (byte) (0x03), (byte) (0x42), (byte) (0x00),
          (byte) (0x04), (byte) (0xee), (byte) (0x5d), (byte) (0x5e),
    (byte) (0xc7), (byte) (0xe1), (byte) (0xc0), (byte) (0xdb),
          (byte) (0x6d), (byte) (0x03), (byte) (0xa6), (byte) (0x7e),
    (byte) (0xe6), (byte) (0xb6), (byte) (0x1b), (byte) (0xec),
          (byte) (0x4d), (byte) (0x6a), (byte) (0x5d), (byte) (0x6a),
    (byte) (0x68), (byte) (0x2e), (byte) (0x0f), (byte) (0xff),
          (byte) (0x7f), (byte) (0x49), (byte) (0x0e), (byte) (0x7d),
    (byte) (0x77), (byte) (0x1f), (byte) (0x44), (byte) (0x22),
          (byte) (0x6d), (byte) (0xbd), (byte) (0xb1), (byte) (0xaf),
    (byte) (0xfa), (byte) (0x16), (byte) (0xcb), (byte) (0xc7),
          (byte) (0xad), (byte) (0xc5), (byte) (0x77), (byte) (0xd2),
    (byte) (0x56), (byte) (0x9c), (byte) (0xaa), (byte) (0xb7),
          (byte) (0xb0), (byte) (0x2d), (byte) (0x54), (byte) (0x01),
    (byte) (0x5d), (byte) (0x3e), (byte) (0x43), (byte) (0x2b),
          (byte) (0x2a), (byte) (0x8e), (byte) (0xd7), (byte) (0x4e),
    (byte) (0xec), (byte) (0x48), (byte) (0x75), (byte) (0x41),
          (byte) (0xa4), (byte) (0xa3), (byte) (0x63), (byte) (0x30),
    (byte) (0x61), (byte) (0x30), (byte) (0x1d), (byte) (0x06),
          (byte) (0x03), (byte) (0x55), (byte) (0x1d), (byte) (0x0e),
    (byte) (0x04), (byte) (0x16), (byte) (0x04), (byte) (0x14),
          (byte) (0xc8), (byte) (0xad), (byte) (0xe9), (byte) (0x77),
    (byte) (0x4c), (byte) (0x45), (byte) (0xc3), (byte) (0xa3),
          (byte) (0xcf), (byte) (0x0d), (byte) (0x16), (byte) (0x10),
    (byte) (0xe4), (byte) (0x79), (byte) (0x43), (byte) (0x3a),
          (byte) (0x21), (byte) (0x5a), (byte) (0x30), (byte) (0xcf),
    (byte) (0x30), (byte) (0x1f), (byte) (0x06), (byte) (0x03),
          (byte) (0x55), (byte) (0x1d), (byte) (0x23), (byte) (0x04),
    (byte) (0x18), (byte) (0x30), (byte) (0x16), (byte) (0x80),
          (byte) (0x14), (byte) (0xc8), (byte) (0xad), (byte) (0xe9),
    (byte) (0x77), (byte) (0x4c), (byte) (0x45), (byte) (0xc3),
          (byte) (0xa3), (byte) (0xcf), (byte) (0x0d), (byte) (0x16),
    (byte) (0x10), (byte) (0xe4), (byte) (0x79), (byte) (0x43),
          (byte) (0x3a), (byte) (0x21), (byte) (0x5a), (byte) (0x30),
    (byte) (0xcf), (byte) (0x30), (byte) (0x0f), (byte) (0x06),
          (byte) (0x03), (byte) (0x55), (byte) (0x1d), (byte) (0x13),
    (byte) (0x01), (byte) (0x01), (byte) (0xff), (byte) (0x04),
          (byte) (0x05), (byte) (0x30), (byte) (0x03), (byte) (0x01),
    (byte) (0x01), (byte) (0xff), (byte) (0x30), (byte) (0x0e),
          (byte) (0x06), (byte) (0x03), (byte) (0x55), (byte) (0x1d),
    (byte) (0x0f), (byte) (0x01), (byte) (0x01), (byte) (0xff),
          (byte) (0x04), (byte) (0x04), (byte) (0x03), (byte) (0x02),
    (byte) (0x02), (byte) (0x84), (byte) (0x30), (byte) (0x0a),
          (byte) (0x06), (byte) (0x08), (byte) (0x2a), (byte) (0x86),
    (byte) (0x48), (byte) (0xce), (byte) (0x3d), (byte) (0x04),
          (byte) (0x03), (byte) (0x02), (byte) (0x03), (byte) (0x47),
    (byte) (0x00), (byte) (0x30), (byte) (0x44), (byte) (0x02),
          (byte) (0x20), (byte) (0x35), (byte) (0x21), (byte) (0xa3),
    (byte) (0xef), (byte) (0x8b), (byte) (0x34), (byte) (0x46),
          (byte) (0x1e), (byte) (0x9c), (byte) (0xd5), (byte) (0x60),
    (byte) (0xf3), (byte) (0x1d), (byte) (0x58), (byte) (0x89),
          (byte) (0x20), (byte) (0x6a), (byte) (0xdc), (byte) (0xa3),
    (byte) (0x65), (byte) (0x41), (byte) (0xf6), (byte) (0x0d),
          (byte) (0x9e), (byte) (0xce), (byte) (0x8a), (byte) (0x19),
    (byte) (0x8c), (byte) (0x66), (byte) (0x48), (byte) (0x60),
          (byte) (0x7b), (byte) (0x02), (byte) (0x20), (byte) (0x4d),
    (byte) (0x0b), (byte) (0xf3), (byte) (0x51), (byte) (0xd9),
          (byte) (0x30), (byte) (0x7c), (byte) (0x7d), (byte) (0x5b),
    (byte) (0xda), (byte) (0x35), (byte) (0x34), (byte) (0x1d),
          (byte) (0xa8), (byte) (0x47), (byte) (0x1b), (byte) (0x63),
    (byte) (0xa5), (byte) (0x85), (byte) (0x65), (byte) (0x3c),
          (byte) (0xad), (byte) (0x4f), (byte) (0x24), (byte) (0xa7),
    (byte) (0xe7), (byte) (0x4d), (byte) (0xaf), (byte) (0x41),
          (byte) (0x7d), (byte) (0xf1), (byte) (0xbf),
    };
  //notBefore Time UTCTime 2016-01-11 00:46:09 UTC
  private static final byte[] notBefore = {
      0x17, 0x0D, 0x31, 0x36, 0x30, 0x31,
      0x31, 0x31, 0x30, 0x30, 0x34, 0x36, 0x30, 0x39, 0x5A};
  //notAfter Time UTCTime 2026-01-08 00:46:09 UTC
  private static final byte[] notAfter = {
      0x17, 0x0D, 0x32, 0x36, 0x30, 0x31, 0x30,
      0x38, 0x30, 0x30, 0x34, 0x36, 0x30, 0x39, 0x5A};

  private static final byte[] creationTimeMs = {
      0x01,(byte)(0x87), (byte)(0xE2),0x2F,(byte)(0x82),0x53
  };

  private CardSimulator simulator;
  private AID ndefApplet;
  private AID presentationApplet;
  private AID provisioningApplet;
  public FunctionalTest() {
    simulator = new CardSimulator();
    ndefApplet = AIDUtil.create(NdefTagApplet.AID_NDEF_TAG_APPLET);
    presentationApplet = AIDUtil.create(PresentationApplet.AID_MDL_DIRECT_ACCESS_APPLET);
    provisioningApplet = AIDUtil.create(ProvisioningApplet.DIRECT_ACCESS_PROVISIONING_APPLET_ID);
  }

  private void init(){
    simulator.installApplet(ndefApplet, NdefTagApplet.class);
    simulator.installApplet(presentationApplet, PresentationApplet.class);
    simulator.installApplet(provisioningApplet, ProvisioningApplet.class);
    // Select applet
    simulator.selectApplet(provisioningApplet);
  }

@Test
  public void test(){
    System.out.println("Do nothing");
}

  //   CredentialData = {
  //     "docType": tstr,
  //     "issuerNameSpaces": IssuerNameSpaces,
  //     "issuerAuth" : IssuerAuth,
  //     "readerAccess" : ReaderAccess
  //   }

public byte[] extractCredDataFromResponse(String response){
   DataItem deviceResponse = com.android.identity.internal.Util.cborDecode(
      com.android.identity.internal.Util.fromHex(response));
  DataItem documentDataItem = com.android.identity.internal.Util.cborMapExtractArray(deviceResponse, "documents").get(0);
  String docType = com.android.identity.internal.Util.cborMapExtractString(documentDataItem, "docType");
  DataItem issuerSigned = com.android.identity.internal.Util.cborMapExtractMap(documentDataItem, "issuerSigned");
  DataItem nameSpaces = com.android.identity.internal.Util.cborMapExtractMap(issuerSigned, "nameSpaces");
  DataItem issuerAuthDataItem = com.android.identity.internal.Util.cborMapExtract(issuerSigned, "issuerAuth");
  byte[] issuerAuth = com.android.identity.internal.Util.cborEncode(issuerAuthDataItem);
  byte[] issuerNameSpaces = com.android.identity.internal.Util.cborEncode(nameSpaces);
  PublicKey readerKey = null;
  try {
    CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
    X509Certificate cert = (X509Certificate) certFactory.generateCertificate(
        new ByteArrayInputStream(
            com.android.identity.internal.Util.fromHex(
                TestVectors.ISO_18013_5_ANNEX_D_READER_CERT)));
    readerKey = cert.getPublicKey();
  }catch(Exception e){
    e.printStackTrace();
  }
  ECPoint point = (( java.security.interfaces.ECPublicKey)readerKey).getW();
  byte[] x = point.getAffineX().toByteArray();
  byte[] y = point.getAffineY().toByteArray();
  byte[] key = new byte[65];
  key[0] = 0x04;
  Util.arrayCopyNonAtomic(x,(short)1, key, (short)1,(short) 32);
  Util.arrayCopyNonAtomic(y,(short)1, key, (short)33,(short) 32);
  print(key, (short)0, (short)key.length);

  Map credData = new Map();
  credData.put(new UnicodeString("docType"),new UnicodeString(docType));
  credData.put(new UnicodeString("issuerNameSpaces"),nameSpaces);
  credData.put(new UnicodeString("issuerAuth"),issuerAuthDataItem);
  credData.put(new UnicodeString("readerAccess"),new Array().add(new ByteString(key)));
  byte[] credDataBytes = com.android.identity.internal.Util.cborEncode(credData);
  print(credDataBytes,(short) 0, (short) credDataBytes.length);
  return credDataBytes;
}
  @Test
  public void testDirectAccessStoreProvisioning_Success(){
    // Init the applet
    init();
    // Get information
    CommandAPDU cmd = makeGetInformation();
    ResponseAPDU resp = simulator.transmitCommand(cmd);
    Assert.assertEquals(0x9000, resp.getSW());
    // Store the factory attest key
    cmd = makeStoreFactoryAttestKeys();
    resp = simulator.transmitCommand(cmd);
    Assert.assertEquals(0x9000, resp.getSW());
    // Create the credential doc
    cmd = makeCredentialDoc();
    resp = simulator.transmitCommand(cmd);
    Assert.assertEquals(0x9000, resp.getSW());
    // Generate presentation package
    cmd = makeCreatePresentationPkg();
    resp = simulator.transmitCommand(cmd);
    Assert.assertEquals(0x9000, resp.getSW());
    // Validate the resp
    byte[] respData = resp.getData();
    CBORDecoder decoder = new CBORDecoder();
    decoder.initialize(respData, (short)0, (short) respData.length);
    decoder.readMajorType(CBORBase.TYPE_MAP);
    byte key = decoder.readInt8();
    Assert.assertEquals(MdlSpecifications.KEY_CERT,key);
    Assert.assertEquals(CBORBase.TYPE_BYTE_STRING, decoder.getMajorType());
    // TODO add the cert validation
    decoder.skipEntry();
    key = decoder.readInt8();
    Assert.assertEquals(MdlSpecifications.KEY_ENC_DATA,key);
    // Extract the encrypted presentation pkg
    byte[] data = new byte[2048];
    short dataLen = decoder.readByteString(data,(short) 0);
    // save encrypted data for future use
    byte[] presentationPkg = new byte[dataLen];
    Util.arrayCopyNonAtomic(data, (short)0, presentationPkg, (short)0,
        dataLen);
    SEProvider.print(presentationPkg, (short)0, dataLen);
    // decrypt the presentation pkg
    dataLen = decryptData((byte)0, data,(short) 0, dataLen);
    SEProvider.print(data,(short)0, dataLen);
    // validate the decrypted data
    decoder.initialize(data,(short) 0, dataLen);
    decoder.readMajorType(CBORBase.TYPE_ARRAY);
    byte[] privateKey = new byte[128];
    short privKeyLen = decoder.readByteString(privateKey,(short) 0);
    Assert.assertEquals((short)32, privKeyLen);
    Assert.assertEquals(CBORBase.ENCODED_NULL, decoder.getRawByte());

    // begin provisioning using the encrypted presentation pkg received earlier
    cmd = makeProvisionData(presentationPkg, (short)0, (short)presentationPkg.length,
        ProvisioningApplet.BEGIN);
    resp = simulator.transmitCommand(cmd);
    Assert.assertEquals(0x9000, resp.getSW());
    data = resp.getData();
    SEProvider.print(data,(short)0, (short) data.length);

    byte[] credData = extractCredDataFromResponse(TestVectors.ISO_18013_5_ANNEX_D_DEVICE_RESPONSE);
    byte[] doc = new byte[credData.length + 3];
    CBOREncoder encoder = new CBOREncoder();
    encoder.initialize(doc, (short)0, (short)doc.length);
    encoder.encodeByteString(credData, (short)0, (short) credData.length);
    SEProvider.print(doc,(short)0, (short) doc.length);
     byte[] nonce = new byte[SEProvider.AES_GCM_NONCE_LENGTH];
    // First 3 bytes is the header
    decoder.initialize(data, (short)0, (short)data.length);
    dataLen = decoder. readMajorType(CBORBase.TYPE_BYTE_STRING);
    byte[] acc = new byte[presentationPkg.length + doc.length];
    short accCur = Util.arrayCopyNonAtomic(data, decoder.getCurrentOffset(), acc, (short) 0,
        dataLen);
    SEProvider.print(acc, (short)0, SEProvider.AES_GCM_NONCE_LENGTH);

    // update provisioning data by passing clear text credential data
    int remainingSize = doc.length;
    short sentSize = 0;
    short docStart = accCur;
    while(remainingSize > 1008) {
      cmd = makeProvisionData(doc, sentSize, (short) 1008, ProvisioningApplet.UPDATE);
      resp = simulator.transmitCommand(cmd);
      Assert.assertEquals(0x9000, resp.getSW());
      data = resp.getData();
      SEProvider.print(data, (short) 0, (short) data.length);
      decoder.initialize(data, (short)0, (short) data.length);
      dataLen = decoder.readByteString(acc,accCur);
      accCur += dataLen;
      SEProvider.print(acc, (short) 0, accCur);
      sentSize += 1008;
      remainingSize -= 1008;
    }
    // finish provisioning
    cmd = makeProvisionData(doc, (short) sentSize, (short) remainingSize,ProvisioningApplet.FINISH);
    resp = simulator.transmitCommand(cmd);
    Assert.assertEquals(0x9000, resp.getSW());
    data = resp.getData();
    SEProvider.print(data, (short) 0, (short) data.length);
    decoder.initialize(data, (short)0, (short) data.length);
    dataLen = decoder.readByteString(acc,accCur);
    accCur += dataLen;
    byte[] buf = new byte[accCur];
    Util.arrayCopyNonAtomic(acc, (short)0, buf, (short)0, accCur);
    dataLen = decryptData((byte)0, acc,(short)0,accCur);
    SEProvider.print(acc, (short) 0, dataLen);

    // Validate the data
    decoder.initialize(acc, (short)0, dataLen);
    short ret = decoder.readMajorType(CBORBase.TYPE_ARRAY);
    Assert.assertEquals((short) 2, ret);
    ret = decoder.readMajorType(CBORBase.TYPE_BYTE_STRING);
    Assert.assertEquals(privKeyLen, ret);
    decoder.increaseOffset(ret);
    ret = decoder.readMajorType(CBORBase.TYPE_BYTE_STRING);
    Assert.assertEquals((short) credData.length, ret);
    ret = Util.arrayCompare(acc, decoder.getCurrentOffset(), credData, (short)0, (short)credData.length);
    Assert.assertEquals((short)0, ret);

    // Swap in the data
    // begin
    cmd = makeSwapInData(buf, (short)0, (short)1008, ProvisioningApplet.BEGIN);
    resp = simulator.transmitCommand(cmd);
    Assert.assertEquals(0x9000, resp.getSW());
    sentSize = 1008;
    remainingSize = (buf.length - 1008);
    // update
    while(remainingSize > 1008) {
      cmd = makeSwapInData(buf, sentSize, (short) 1008, ProvisioningApplet.UPDATE);
      resp = simulator.transmitCommand(cmd);
      Assert.assertEquals(0x9000, resp.getSW());
      sentSize += 1008;
      remainingSize -= 1008;
    }
    // finish
    cmd = makeSwapInData(buf, (short) sentSize, (short) remainingSize,ProvisioningApplet.FINISH);
    resp = simulator.transmitCommand(cmd);
    Assert.assertEquals(0x9000, resp.getSW());

    cmd = makeLookUpCred((byte) 0);
    resp = simulator.transmitCommand(cmd);
    Assert.assertEquals(0x9000, resp.getSW());

    cmd = makeDeleteCred((byte) 0);
    resp = simulator.transmitCommand(cmd);
    Assert.assertEquals(0x9000, resp.getSW());

    cmd = makeLookUpCred((byte) 0);
    resp = simulator.transmitCommand(cmd);
    Assert.assertNotEquals(0x9000, resp.getSW());
  }

  short decryptData(byte slot, byte[] encData, short start, short len){
    CBORDecoder decoder = new CBORDecoder();
    byte[] nonce = new byte[SEProvider.AES_GCM_NONCE_LENGTH];
    Util.arrayCopyNonAtomic(encData, (short) 0, nonce, (short) 0, SEProvider.AES_GCM_NONCE_LENGTH);
    SEProvider.print(nonce, (short) 0, SEProvider.AES_GCM_NONCE_LENGTH);
    Mdoc doc = ProvisioningApplet.findDocument((byte)0);
    AESKey storageKey = doc.getStorageKey();
    byte[] authData = new byte[128];
    byte[] outBuf = new byte[len];
    short authDataLen = ((ECPublicKey)doc.getCredentialKey().getPublic()).getW(authData, (short) 0);
    len = SEProvider.aesGCMDecryptOneShot(storageKey,encData,SEProvider.AES_GCM_NONCE_LENGTH,
        (short) (len -SEProvider.AES_GCM_NONCE_LENGTH),outBuf,(short) 0,
        nonce,(short)0,SEProvider.AES_GCM_NONCE_LENGTH,
        authData, (short)0, authDataLen,false);
    Util.arrayCopyNonAtomic(outBuf, (short)0, encData, start, len);
    return len;
  }
  @Test
  public void testSelectFile() {
    init();
    byte[] buf1 = {(byte)((NdefTagApplet.FILE_ID_CAPS_CONTAINER >> 8) & 0xFF),
        (byte)(NdefTagApplet.FILE_ID_CAPS_CONTAINER & 0xFF)};
    byte[] buf2 = {(byte)((NdefTagApplet.FILE_ID_NDEF_FILE >> 8) & 0xFF),
        (byte)(NdefTagApplet.FILE_ID_NDEF_FILE & 0xFF)};

    // Select CC File
    CommandAPDU cmd = makeCommandApdu((byte)0, NdefTagApplet.INS_SELECT, (byte)0, (byte)0x0C, buf1, (short)0,
        (short) buf1.length,
        false);
    ResponseAPDU resp = simulator.transmitCommand(cmd);
    Assert.assertNotEquals((short)0x9000, resp.getSW());

    // Select Ndef File
    cmd = makeCommandApdu((byte)0, NdefTagApplet.INS_SELECT, (byte)0, (byte)0x0C, buf2, (short)0,
        (short) buf2.length,
        false);
    resp = simulator.transmitCommand(cmd);
    Assert.assertNotEquals((short)0x9000, resp.getSW());
  }

  @Test
  public void testReadBinaryCC(){
    init();
    simulator.selectApplet(ndefApplet);
    byte[] cc = {(byte)((NdefTagApplet.FILE_ID_CAPS_CONTAINER >> 8) & 0xFF),
        (byte)(NdefTagApplet.FILE_ID_CAPS_CONTAINER & 0xFF)};
    CommandAPDU cmd = makeCommandApdu((byte)0, NdefTagApplet.INS_SELECT, (byte)0, (byte)0x0C, cc, (short)0,
        (short) cc.length,
        false);
    ResponseAPDU resp = simulator.transmitCommand(cmd);
    Assert.assertNotEquals((short)0x9000, resp.getSW());
    cc = resp.getBytes();

    cmd = new CommandAPDU((byte)0, NdefTagApplet.INS_READ_BINARY,(byte)0, (byte)0x00,
        NdefTagApplet.CAPS_CONTAINER.length);
    resp = simulator.transmitCommand(cmd);
    Assert.assertNotEquals((short)0x9000, resp.getSW());
    cc = resp.getData();

    System.out.println("Caps File:");
    print(cc, (short)0, (short)cc.length);

    // Check that length of CC file is at least 15 bytes
    Assert.assertFalse(cc.length < 15);
    // Check the version
    Assert.assertEquals(0x20, cc[2]);
    // Check max read size i.e. response length is at least 15
    Assert.assertFalse(Util.getShort(cc, (byte)3) < 15 );
    // Check max command size must be at least 1
    Assert.assertFalse(Util.getShort(cc, (byte)5) < 1 );
    // Check Ndef file id
    byte[] val = new byte[2];
    Util.arrayCopyNonAtomic(cc, (short)9, val, (short)0, (short)2);
    Assert.assertArrayEquals(new byte[]{(byte)0xE1,4}, val);
    // Check max file size for 2.0 version
    Assert.assertFalse((Util.getShort(cc, (short)11) < 5) ||
        ((cc[11] << 8 | (cc[12] & 0xff)) > 0x7fff));
    // Check NDEF as Read Only
    Assert.assertEquals(0, cc[13]);
    Assert.assertEquals(0xFF, cc[14] & 0x00FF);
  }

  @Test
  public void testSessionEstablishmentAndTermination() {
    init();
    simulator.selectApplet(ndefApplet);
    byte[] ndef = {(byte)((NdefTagApplet.FILE_ID_NDEF_FILE >> 8) & 0xFF),
        (byte)(NdefTagApplet.FILE_ID_NDEF_FILE & 0xFF)};
    CommandAPDU cmd = makeCommandApdu((byte)0, NdefTagApplet.INS_SELECT, (byte)0, (byte)0x0C, ndef, (short)0,
        (short) ndef.length,
        false);
    ResponseAPDU resp = simulator.transmitCommand(cmd);
    Assert.assertNotEquals((short)0x9000, resp.getSW());

    cmd = new CommandAPDU((byte)0, NdefTagApplet.INS_READ_BINARY,(byte)0, (byte)0x00,
        (short)2);
    resp = simulator.transmitCommand(cmd);
    Assert.assertNotEquals((short)0x9000, resp.getSW());
    ndef = resp.getData();

    cmd = new CommandAPDU((byte)0, NdefTagApplet.INS_READ_BINARY,(byte)0, (byte)2,
        (short)(Util.getShort(ndef,(short)0)-2));
    resp = simulator.transmitCommand(cmd);
    Assert.assertNotEquals((short)0x9000, resp.getSW());

    ndef = resp.getData();
    System.out.println("Ndef File:");
    print(ndef, (short)0, (short)ndef.length);
    VerificationHelper reader = performDeviceEngagement(ndef);
    provisionData();
    simulator.selectApplet(presentationApplet);
    byte[] devReq = TestUtil.fromHex(TestVectors.ISO_18013_5_ANNEX_D_DEVICE_REQUEST);
    print(devReq, (short) 0, (short)devReq.length);
    sendSessionEstablishment(reader, devReq);
  }

  VerificationHelper performDeviceEngagement(byte[] ndef){
    // Test with verification helper
    MdlTest.simulator = simulator;
    MdlTest.mData = new byte[ndef.length];
    Util.arrayCopyNonAtomic(ndef, (short)0, MdlTest.mData, (short) 0, (short)ndef.length);
    VerificationHelper reader = new VerificationHelper();
    reader.startListening();
    reader.nfcProcessOnTagDiscovered(new String[]{MdlTest.getNdefTechName(),
        MdlTest.getIosDepTechName()});
    return reader;
  }

  void sendSessionEstablishment(VerificationHelper reader, byte[] request){
    List<DataRetrievalAddress> addresses = MdlTest.mAddresses;
    reader.connect(addresses.get(0));
    reader.sendRequest(request);
  }

  byte[] generateDeviceEngagement(List<DataRetrievalAddress> listeningAddresses)
      throws NoSuchAlgorithmException {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
    kpg.initialize(256);
    KeyPair kp = kpg.generateKeyPair();
    DataItem eDeviceKeyBytes = TestUtil.cborBuildTaggedByteString(
        TestUtil.cborEncode(TestUtil.cborBuildCoseKey(kp.getPublic())));

    DataItem securityDataItem = new CborBuilder()
        .addArray()
        .add(1) // cipher suite
        .add(eDeviceKeyBytes)
        .end()
        .build().get(0);

    DataItem deviceRetrievalMethodsDataItem = null;
    CborBuilder builder = new CborBuilder();
    MapBuilder<CborBuilder> map = builder.addMap();
    map.put(0, "1.0").put(new UnsignedInteger(1), securityDataItem);
    if (deviceRetrievalMethodsDataItem != null) {
      map.put(new UnsignedInteger(2), deviceRetrievalMethodsDataItem);
    }
    map.end();
    return TestUtil.cborEncode(builder.build().get(0));
  }

  public void provisionData(){
    simulator.selectApplet(provisioningApplet);
    // Get information
    CommandAPDU cmd = makeGetInformation();
    ResponseAPDU resp = simulator.transmitCommand(cmd);
    Assert.assertEquals(0x9000, resp.getSW());
    // Store the factory attest key
    cmd = makeStoreFactoryAttestKeys();
    resp = simulator.transmitCommand(cmd);
    Assert.assertEquals(0x9000, resp.getSW());
    // Create the credential doc
    cmd = makeCredentialDoc();
    resp = simulator.transmitCommand(cmd);
    Assert.assertEquals(0x9000, resp.getSW());
    // Generate presentation package
    cmd = makeCreatePresentationPkg();
    resp = simulator.transmitCommand(cmd);
    Assert.assertEquals(0x9000, resp.getSW());
    // Validate the resp
    byte[] respData = resp.getData();
    CBORDecoder decoder = new CBORDecoder();
    decoder.initialize(respData, (short)0, (short) respData.length);
    decoder.readMajorType(CBORBase.TYPE_MAP);
    byte key = decoder.readInt8();
    Assert.assertEquals(MdlSpecifications.KEY_CERT,key);
    Assert.assertEquals(CBORBase.TYPE_BYTE_STRING, decoder.getMajorType());
    // TODO add the cert validation
    decoder.skipEntry();
    key = decoder.readInt8();
    Assert.assertEquals(MdlSpecifications.KEY_ENC_DATA,key);
    // Extract the encrypted presentation pkg
    byte[] data = new byte[2048];
    short dataLen = decoder.readByteString(data,(short) 0);
    // save encrypted data for future use
    byte[] presentationPkg = new byte[dataLen];
    Util.arrayCopyNonAtomic(data, (short)0, presentationPkg, (short)0,
        dataLen);
    SEProvider.print(presentationPkg, (short)0, dataLen);
    // decrypt the presentation pkg
    dataLen = decryptData((byte)0, data,(short) 0, dataLen);
    SEProvider.print(data,(short)0, dataLen);
    // validate the decrypted data
    decoder.initialize(data,(short) 0, dataLen);
    decoder.readMajorType(CBORBase.TYPE_ARRAY);
    byte[] privateKey = new byte[128];
    short privKeyLen = decoder.readByteString(privateKey,(short) 0);
    Assert.assertEquals((short)32, privKeyLen);
    Assert.assertEquals(CBORBase.ENCODED_NULL, decoder.getRawByte());

    // begin provisioning using the encrypted presentation pkg received earlier
    cmd = makeProvisionData(presentationPkg, (short)0, (short)presentationPkg.length,
        ProvisioningApplet.BEGIN);
    resp = simulator.transmitCommand(cmd);
    Assert.assertEquals(0x9000, resp.getSW());
    data = resp.getData();
    SEProvider.print(data,(short)0, (short) data.length);

    byte[] credData = extractCredDataFromResponse(TestVectors.ISO_18013_5_ANNEX_D_DEVICE_RESPONSE);
    byte[] doc = new byte[credData.length + 3];
    CBOREncoder encoder = new CBOREncoder();
    encoder.initialize(doc, (short)0, (short)doc.length);
    encoder.encodeByteString(credData, (short)0, (short) credData.length);
    SEProvider.print(doc,(short)0, (short) doc.length);
    byte[] nonce = new byte[SEProvider.AES_GCM_NONCE_LENGTH];
    // First 3 bytes is the header
    decoder.initialize(data, (short)0, (short)data.length);
    dataLen = decoder. readMajorType(CBORBase.TYPE_BYTE_STRING);
    byte[] acc = new byte[presentationPkg.length + doc.length];
    short accCur = Util.arrayCopyNonAtomic(data, decoder.getCurrentOffset(), acc, (short) 0,
        dataLen);
    SEProvider.print(acc, (short)0, SEProvider.AES_GCM_NONCE_LENGTH);

    // update provisioning data by passing clear text credential data
    int remainingSize = doc.length;
    short sentSize = 0;
    short docStart = accCur;
    while(remainingSize > 1008) {
      cmd = makeProvisionData(doc, sentSize, (short) 1008, ProvisioningApplet.UPDATE);
      resp = simulator.transmitCommand(cmd);
      Assert.assertEquals(0x9000, resp.getSW());
      data = resp.getData();
      SEProvider.print(data, (short) 0, (short) data.length);
      decoder.initialize(data, (short)0, (short) data.length);
      dataLen = decoder.readByteString(acc,accCur);
      accCur += dataLen;
      SEProvider.print(acc, (short) 0, accCur);
      sentSize += 1008;
      remainingSize -= 1008;
    }
    // finish provisioning
    cmd = makeProvisionData(doc, (short) sentSize, (short) remainingSize,ProvisioningApplet.FINISH);
    resp = simulator.transmitCommand(cmd);
    Assert.assertEquals(0x9000, resp.getSW());
    data = resp.getData();
    SEProvider.print(data, (short) 0, (short) data.length);
    decoder.initialize(data, (short)0, (short) data.length);
    dataLen = decoder.readByteString(acc,accCur);
    accCur += dataLen;
    byte[] buf = new byte[accCur];
    Util.arrayCopyNonAtomic(acc, (short)0, buf, (short)0, accCur);
    dataLen = decryptData((byte)0, acc,(short)0,accCur);
    SEProvider.print(acc, (short) 0, dataLen);

    // Validate the data
    decoder.initialize(acc, (short)0, dataLen);
    short ret = decoder.readMajorType(CBORBase.TYPE_ARRAY);
    Assert.assertEquals((short) 2, ret);
    ret = decoder.readMajorType(CBORBase.TYPE_BYTE_STRING);
    Assert.assertEquals(privKeyLen, ret);
    decoder.increaseOffset(ret);
    ret = decoder.readMajorType(CBORBase.TYPE_BYTE_STRING);
    Assert.assertEquals((short) credData.length, ret);
    ret = Util.arrayCompare(acc, decoder.getCurrentOffset(), credData, (short)0, (short)credData.length);
    Assert.assertEquals((short)0, ret);

    // Swap in the data
    // begin
    cmd = makeSwapInData(buf, (short)0, (short)1008, ProvisioningApplet.BEGIN);
    resp = simulator.transmitCommand(cmd);
    Assert.assertEquals(0x9000, resp.getSW());
    sentSize = 1008;
    remainingSize = (buf.length - 1008);
    // update
    while(remainingSize > 1008) {
      cmd = makeSwapInData(buf, sentSize, (short) 1008, ProvisioningApplet.UPDATE);
      resp = simulator.transmitCommand(cmd);
      Assert.assertEquals(0x9000, resp.getSW());
      sentSize += 1008;
      remainingSize -= 1008;
    }
    // finish
    cmd = makeSwapInData(buf, (short) sentSize, (short) remainingSize,ProvisioningApplet.FINISH);
    resp = simulator.transmitCommand(cmd);
    Assert.assertEquals(0x9000, resp.getSW());
  }
  @Test
  public void testProvisioning(){
/*    init();
    AID appletAID2 = AIDUtil.create(PresentationApplet.AID_MDL_DIRECT_ACCESS_APPLET);
    simulator.selectApplet(appletAID2);
    testDirectAccessStoreProvisioning_Success();
 */
 /*   byte[] keyBytes = new byte[65];
    keyBytes[0] = 0x04;
    byte[] x = TestUtil.fromHex(TestVectors.ISO_18013_5_ANNEX_D_STATIC_DEVICE_KEY_X);
    byte[] y= TestUtil.fromHex(TestVectors.ISO_18013_5_ANNEX_D_STATIC_DEVICE_KEY_Y);
    short offset = Util.arrayCopyNonAtomic(x,(short)0, keyBytes, (short)1, (short) x.length);
    offset = Util.arrayCopyNonAtomic(y,(short)0, keyBytes, offset, (short) y.length);
    byte[] d= TestUtil.fromHex(TestVectors.ISO_18013_5_ANNEX_D_STATIC_DEVICE_KEY_D);
    ECPrivateKey privKey = (ECPrivateKey) KeyBuilder.buildKey(
        KeyBuilder.TYPE_EC_FP_PRIVATE,
        KeyBuilder.LENGTH_EC_FP_256, false);
    privKey.setS(d,(short)0,(short) d.length);
    ECPublicKey pubKey = (ECPublicKey) KeyBuilder.buildKey(
        KeyBuilder.TYPE_EC_FP_PUBLIC,
        KeyBuilder.LENGTH_EC_FP_256, false);
    pubKey.setW(keyBytes,(short)0,(short) keyBytes.length);
    Signature signer =      Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
    signer.init(privKey, Signature.MODE_SIGN);
    Signature verifier = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
    verifier.init(pubKey, Signature.MODE_VERIFY);
    byte[] hello = "hello".getBytes();
    byte[] signature = new byte[128];
    short len = signer.sign(hello,(short)0,(short)hello.length,signature,(short)0);
    boolean verified = verifier.verify(hello,(short)0,(short)hello.length,signature,(short)0, len);

  */
    }
  @Test
  public void printReaderRoot(){
    byte[] bytes = TestUtil.fromHex(TestVectors.reader_root);
    print(bytes, (short)0, (short) bytes.length);
  }
  @Test
  public void printSessionEstablishment(){
    byte[] bytes = TestUtil.fromHex(TestVectors.ISO_18013_5_ANNEX_D_SESSION_ESTABLISHMENT);
    print(bytes, (short)0, (short) bytes.length);
  }

  @Test
  public void printDeviceResponse(){
    byte[] bytes = TestUtil.fromHex(TestVectors.ISO_18013_5_ANNEX_D_DEVICE_RESPONSE);
    print(bytes, (short)0, (short) bytes.length);
  }

  @Test
  public void printDeviceRequest(){
    byte[] bytes = TestUtil.fromHex(TestVectors.ISO_18013_5_ANNEX_D_DEVICE_REQUEST);
    print(bytes, (short)0, (short) bytes.length);
  }

  @Test
  public void printMdlDocument(){
    byte[] bytes = TestUtil.fromHex(TestVectors.MDL_DOCUMENT);
    print(bytes, (short)0, (short) bytes.length);
  }
  @Test
  public void printCredData(){
    byte[] bytes = TestUtil.fromHex(TestVectors.CRED_DATA);
    print(bytes, (short)0, (short) bytes.length);
  }

  @Test
  public void printReaderCert(){
    byte[] bytes = TestUtil.fromHex(TestVectors.ISO_18013_5_ANNEX_D_READER_CERT);
    print(bytes, (short)0, (short) bytes.length);
  }

  @Test
  public void printExampleRootCert(){

  }
  public static void print(byte[] buf, short start, short length) {
    StringBuilder sb = new StringBuilder();
    System.out.println("----");
    for (int i = start; i < (start + length); i++) {
      sb.append(String.format("%02X", buf[i]));
    }
    System.out.println(sb);
  }
  private CommandAPDU makeCommandApdu(byte cla, byte ins, byte p1, byte p2, byte[]buf, short index, short len,
      boolean ext) {
    byte[] apdu;
    if(len > 256 || ext) {
      apdu = new byte[7 + len];
      apdu[0] = cla;
      apdu[1] = ins;
      apdu[2] = p1;
      apdu[3] = p2;
      apdu[4] = 0;
      Util.setShort(apdu, (short) 5, len);
      if(buf != null) {
        Util.arrayCopyNonAtomic(buf, index, apdu, (short) 7, len);
        print(apdu, (short) 7, len);
      }
    }else {
      apdu = new byte[5 + len];
      apdu[0] = cla;
      apdu[1] = ins;
      apdu[2] = p1;
      apdu[3] = p2;
      apdu[4] = (byte)len;
      if(buf != null) {
        Util.arrayCopyNonAtomic(buf, index, apdu, (short) 5, len);
        print(apdu, (short) 5, len);
      }
    }
    return new CommandAPDU(apdu);
  }

  //Lookup Credential
  private CommandAPDU makeLookUpCred(byte slot){
    byte[] buf = {
        slot, ProvisioningApplet.CMD_MDOC_LOOKUP,
    };
    return makeCommandApdu((byte)0, ProvisioningApplet.INS_ENVELOPE, (byte)0, (byte)0, buf, (short)0,
        (short)buf.length,
        false);
  }


  // Delete Credential
  private CommandAPDU makeDeleteCred(byte slot){
    byte[] buf = {
        slot, ProvisioningApplet.CMD_MDOC_DELETE_CREDENTIAL,
    };
    return makeCommandApdu((byte)0, ProvisioningApplet.INS_ENVELOPE, (byte)0, (byte)0, buf, (short)0,
        (short)buf.length,
        false);
  }

  // Get Information
  private CommandAPDU makeGetInformation(){
    byte[] buf = {
        0, ProvisioningApplet.CMD_MDOC_GET_INFORMATION,
    };
    return makeCommandApdu((byte)0, ProvisioningApplet.INS_ENVELOPE, (byte)0, (byte)0, buf, (short)0,
        (short)buf.length,
        false);
  }
  private CommandAPDU makeStoreFactoryAttestKeys(){
    byte[] buf = new byte[4096];
    short offset = 0;
    offset = Util.setShort(buf, offset, ProvisioningApplet.TAG_ATT_PUB_KEY_CERT);
    offset = Util.setShort(buf, offset, (short)(kEcAttestCert.length + kEcAttestRootCert.length));
    offset = Util.arrayCopyNonAtomic(kEcAttestCert,(short) 0, buf, offset,
        (short)(kEcAttestCert.length));
    offset = Util.arrayCopyNonAtomic(kEcAttestRootCert,(short) 0, buf, offset,
        (short)(kEcAttestRootCert.length));
    offset = Util.setShort(buf, offset, ProvisioningApplet.TAG_ATT_PRIV_KEY);
    offset = Util.setShort(buf, offset, (short) (kEcAttestPrivateKey.length));
    offset = Util.arrayCopyNonAtomic(kEcAttestPrivateKey,(short) 0, buf, offset,
        (short)(kEcAttestPrivateKey.length));
    return makeCommandApdu((byte)0, ProvisioningApplet.INS_PROVISION_DATA, (byte)0, (byte)0, buf, (short)0,
        offset,
        false);
  }
  private CommandAPDU makeCredentialDoc(){
    byte[] buf = new byte[1024];

    short offset = 0;
    offset = Util.setShort(buf, offset,(short) ProvisioningApplet.CMD_MDOC_CREATE); // Command
    buf[offset++] = 0; // slot is zero
    buf[offset++] = 0; // not a test credential

    offset = Util.setShort(buf,offset,(short)2); // os version len
    offset = Util.setShort(buf, offset, (short)3); // os version = 3

    offset = Util.setShort(buf,offset,(short)2); // os patch level len
    offset = Util.setShort(buf, offset, (short)3); // os patch level = 3

    offset = Util.setShort(buf,offset,(short)2); // challenge length = 2
    offset = Util.setShort(buf, offset, (short)100); // challenge = 100

    offset = Util.setShort(buf,offset,(short)notBefore.length); // notBefore length = 2
    offset = Util.arrayCopyNonAtomic(notBefore, (short) 0, buf, offset,(short) notBefore.length);

    offset = Util.setShort(buf,offset,(short)notAfter.length); // notAfter length = 2
    offset = Util.arrayCopyNonAtomic(notAfter, (short) 0, buf, offset,(short) notAfter.length);

    offset = Util.setShort(buf,offset,(short)creationTimeMs.length); // creationTime length = 2
    offset = Util.arrayCopyNonAtomic(creationTimeMs, (short) 0,
        buf, offset,(short) creationTimeMs.length);

    offset = Util.setShort(buf,offset,(short)2); // app id length = 2
    offset = Util.setShort(buf, offset, (short)2023);

    return makeCommandApdu((byte)0, ProvisioningApplet.INS_ENVELOPE, (byte)0, (byte)0, buf, (short)0, offset,
        true);
  }
  private CommandAPDU makeCreatePresentationPkg(){
    byte[] buf = new byte[1024];

    short offset = 0;
    offset = Util.setShort(buf, offset,(short) ProvisioningApplet.CMD_MDOC_CREATE_PRESENTATION_PKG); // Command
    buf[offset++] = 0; // slot is zero
    offset = Util.setShort(buf,offset,(short)notBefore.length); // notBefore length = 2
    offset = Util.arrayCopyNonAtomic(notBefore, (short) 0, buf, offset,(short) notBefore.length);
    offset = Util.setShort(buf,offset,(short)notAfter.length); // notAfter length = 2
    offset = Util.arrayCopyNonAtomic(notAfter, (short) 0, buf, offset,(short) notAfter.length);

    return makeCommandApdu((byte)0, ProvisioningApplet.INS_ENVELOPE, (byte)0, (byte)0, buf, (short)0, offset,
        true);
  }
  private CommandAPDU makeProvisionData(byte[] data, short start, short len, byte op){

    byte[] buf = new byte[1032];
    short offset = 0;
    offset = Util.setShort(buf, offset,ProvisioningApplet.CMD_MDOC_PROVISION_DATA); // Command
    buf[offset++] = 0; // slot is zero
    buf[offset++] = op;
    CBOREncoder enc = new CBOREncoder();
    enc.initialize(buf, offset, (short)(1032 - offset));
    offset += enc.encodeByteString(data, start, len);
    SEProvider.print(buf, (short) 0, offset);
    return makeCommandApdu((byte)0, ProvisioningApplet.INS_ENVELOPE, (byte)0, (byte)0, buf, (short)0, offset,
        true);
  }
  private CommandAPDU makeSwapInData(byte[] data, short start, short len, byte op){

    byte[] buf = new byte[1032];
    short offset = 0;
    offset = Util.setShort(buf, offset,ProvisioningApplet.CMD_MDOC_SWAP_IN); // Command
    buf[offset++] = 0; // slot is zero
    buf[offset++] = op;
    CBOREncoder enc = new CBOREncoder();
    enc.initialize(buf, offset, (short)(1032 - offset));
    offset += enc.encodeByteString(data, start, len);
    SEProvider.print(buf, (short) 0, offset);
    return makeCommandApdu((byte)0, ProvisioningApplet.INS_ENVELOPE, (byte)0, (byte)0, buf, (short)0, offset,
        true);
  }

  /*
  private key:
      30 77 02 01 01 04 20 21 e0 86 43 2a 15 19 84 59
      cf 36 3a 50 fc 14 c9 da ad f9 35 f5 27 c2 df d7
      1e 4d 6d bc 42 e5 44 a0 0a 06 08 2a 86 48 ce 3d
      03 01 07 a1 44 03 42 00 04 eb 9e 79 f8 42 63 59
      ac cb 2a 91 4c 89 86 cc 70 ad 90 66 93 82 a9 73
      26 13 fe ac cb f8 21 27 4c 21 74 97 4a 2a fe a5
      b9 4d 7f 66 d4 e0 65 10 66 35 bc 53 b7 a0 a3 a6
      71 58 3e db 3e 11 ae 10 14

  Attest Key Cert:
   */
  @Test
  public void printAllElements() {
    String[] elements = {
        "family_name",
        "given_name",
        "birth_date",
        "issue_date",
        "expiry_date",
        "issuing_country",
        "issuing_authority",
        "document_number",
        "portrait",
        "driving_privileges",
        "un_distinguishing_sign",
        "administrative_number",
        "sex",
        "height",
        "weight",
        "eye_colour",
        "hair_colour",
        "birth_place",
        "resident_address",
        "portrait_capture_date",
        "age_in_years",
        "age_birth_year",
        "age_over_NN",
        "issuing_jurisdiction",
        "nationality",
        "resident_city",
        "resident_state",
        "resident_postal_code",
        "resident_country",
        "biometric_template_xx",
        "family_name_national_character",
        "given_name_national_character",
        "signature_usual_mark"
    };
    for (int i = 0; i < elements.length; i++) {
      StringBuilder b = new StringBuilder();
      b.append("//" + '"' + elements[i] + '"'+"\n");
      byte[] str = elements[i].getBytes();
      byte[] txtStr = new byte[str.length + 3];
      CBOREncoder enc = new CBOREncoder();
      enc.initialize(txtStr, (short) 0, (short) txtStr.length);
      enc.encodeTextString(str, (short) 0, (short) str.length);
      b.append("public static final byte[] " + elements[i] + " = {");

      int j = 0;
      if (str.length < 0x18) {
        b.append("0x" + Integer.toHexString(txtStr[j++]) + "," + "\n");
      } else if (str.length < 0x100) {
        b.append("0x" + Integer.toHexString(txtStr[j++]) + ", ");
        b.append("0x" + Integer.toHexString(txtStr[j++]) + "," + "\n");
      } else {
        b.append("0x" + Integer.toHexString(txtStr[j++]) + ", ");
        b.append("0x" + Integer.toHexString(txtStr[j++]) + ", ");
        b.append("0x" + Integer.toHexString(txtStr[j++]) + "," + "\n");
      }
      b.append("\t");
      while (j < (txtStr.length - 2)) {
        b.append("0x" + Integer.toHexString(txtStr[j++]) + ", ");
        if(j%12 == 0){
          b.append("\n\t");
        }
      }
      b.append("\n"+"};\n");
      System.out.println(b.toString());
    }
  }
}
