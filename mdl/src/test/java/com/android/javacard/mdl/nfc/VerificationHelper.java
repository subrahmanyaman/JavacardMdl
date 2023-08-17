package com.android.javacard.mdl.nfc;

import static java.nio.charset.StandardCharsets.UTF_8;


import com.android.identity.mdoc.response.DeviceResponseParser;
import com.android.javacard.mdl.MdlTest;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.OptionalInt;
import java.util.concurrent.Executor;

import co.nstant.in.cbor.CborBuilder;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.SimpleValue;
import androidx.annotation.Nullable;

// copied from com.android.identity.VerificationHelper and stripped down to be useable for unit
// testing;
public class VerificationHelper {
  private static final String TAG = "VerificationHelper";
  DataTransport mDataTransport;
  Listener mListener;
  KeyPair mEphemeralKeyPair;
  SessionEncryptionReader mSessionEncryptionReader;
  byte[] mDeviceEngagement;
  Executor mDeviceResponseListenerExecutor;
  IsoDep mNfcIsoDep;
  DataRetrievalAddress mConnectWaitingForIsoDepAddress;
  // The handover used
  //
  private byte[] mHandover;
  private boolean mUseTransportSpecificSessionTermination;
  private boolean mSendSessionTerminationMessage = true;
  private boolean mIsListening;
  private boolean mUseL2CAP;

  public VerificationHelper() {
    mEphemeralKeyPair = TestUtil.createEphemeralKeyPair();
    mSessionEncryptionReader = null;
    mUseL2CAP = false;
  }


  public void setLoggingFlags( int loggingFlags) {
  }

  public void setUseL2CAP(boolean useL2CAP) {
    mUseL2CAP = useL2CAP;
  }

  public void startListening() {
    mIsListening = true;
  }

  public void nfcProcessOnTagDiscovered( String[] techList) {
    if (!mIsListening) {
      throw new IllegalStateException("Not currently listening");
    }
    for (String tech : techList) {

      if (tech.equals(MdlTest.getNdefTechName())) {
        if (mDeviceEngagement != null) {
        } else {
          setNdefDeviceEngagement(MdlTest.getCachedNdefMessage());
        }
      } else if (tech.equals(MdlTest.getIosDepTechName())) {
        mNfcIsoDep = new IsoDep();
        // If we're doing QR code engagement _and_ NFC data transfer
        // it's possible that we're now in a state where we're
        // waiting for the reader to be in the NFC field... see
        // also comment in connect() for this case...
        if (mConnectWaitingForIsoDepAddress != null) {
         mDeviceResponseListenerExecutor.execute(
              () -> connect(mConnectWaitingForIsoDepAddress)
          );
        }
      }
    }
  }

  void setNdefDeviceEngagement(  NdefMessage m) {
    byte[] handoverSelectMessage;
    byte[] encodedDeviceEngagement = null;
    boolean validHandoverSelectMessage = false;

   // NdefMessage m = ndef.getCachedNdefMessage();

    handoverSelectMessage = m.toByteArray();
    List<DataRetrievalAddress> addresses = new ArrayList<>();
    for (NdefRecord r : m.getRecords()) {

      // Handle Handover Select record for NFC Forum Connection Handover specification
      // version 1.5 (encoded as 0x15 below).
      //
      if (r.getTnf() == NdefRecord.TNF_WELL_KNOWN
          && Arrays.equals(r.getType(), "Hs".getBytes(UTF_8))) {
        byte[] payload = r.getPayload();
        if (payload.length >= 1 && payload[0] == 0x15) {
          // The NDEF payload of the Handover Select Record SHALL consist of a single
          // octet that contains the MAJOR_VERSION and MINOR_VERSION numbers,
          // optionally followed by an embedded NDEF message.
          //
          // If present, the NDEF message SHALL consist of one of the following options:
          // - One or more ALTERNATIVE_CARRIER_RECORDs
          // - One or more ALTERNATIVE_CARRIER_RECORDs followed by an ERROR_RECORD
          // - An ERROR_RECORD.
          //
          //byte[] ndefMessage = Arrays.copyOfRange(payload, 1, payload.length);
          // TODO: check that the ALTERNATIVE_CARRIER_RECORD matches
          //   the ALTERNATIVE_CARRIER_CONFIGURATION record retrieved below.
          validHandoverSelectMessage = true;
        }
      }

      // DeviceEngagement record
      //
      if (r.getTnf() == NdefRecord.TNF_EXTERNAL_TYPE
          && Arrays.equals(r.getType(),
          "iso.org:18013:deviceengagement".getBytes(UTF_8))
          && Arrays.equals(r.getId(), "mdoc".getBytes(UTF_8))) {
        encodedDeviceEngagement = r.getPayload();

      }

      // This parses the various carrier specific NDEF records, see
      // DataTransport.parseNdefRecord() for details.
      //
      if (r.getTnf() == NdefRecord.TNF_MIME_MEDIA) {
        List<DataRetrievalAddress> addressesFromMethod = DataTransport.parseNdefRecord(r);
        if (addressesFromMethod != null) {
          addresses.addAll(addressesFromMethod);
        } else {
//          Log.w(TAG, "Ignoring unrecognized NdefRecord: " + r);
        }
      }

    }

    if (validHandoverSelectMessage && !addresses.isEmpty()) {

      byte[] readerHandover = TestUtil.cborEncode(new CborBuilder()
          .addArray()
          .add(handoverSelectMessage)    // Handover Select message
          .add(SimpleValue.NULL)         // Handover Request message
          .end()
          .build().get(0));
      setDeviceEngagement(encodedDeviceEngagement, readerHandover);
      reportDeviceEngagementReceived(addresses);
    } else {
      reportError(new IllegalArgumentException(
          "Invalid Handover Select message: " + TestUtil.toHex(m.toByteArray())));
    }
  }

  private void setDeviceEngagement( byte[] deviceEngagement,  byte[] handover) {
    if (mDeviceEngagement != null) {
      throw new IllegalStateException("Device Engagement already set");
    }
    mDeviceEngagement = deviceEngagement;
    mHandover = handover;

    mSessionEncryptionReader = new SessionEncryptionReader(
        mEphemeralKeyPair.getPrivate(),
        mEphemeralKeyPair.getPublic(),
        mDeviceEngagement,
        mHandover);
  }

  public void connect( DataRetrievalAddress address) {

    mDataTransport = address.createDataTransport();
    if (mDataTransport instanceof DataTransportNfc) {
      if (mNfcIsoDep == null) {
        // This can happen if using NFC data transfer with QR code engagement
        // which is allowed by ISO 18013-5:2021 (even though it's really
        // weird). In this case we just sit and wait until the tag (reader)
        // is detected... once detected, this routine can just call connect()
        // again.
        mConnectWaitingForIsoDepAddress = address;
        reportMoveIntoNfcField();
        return;
      }
      ((DataTransportNfc) mDataTransport).setIsoDep(mNfcIsoDep);
    }

    // Careful, we're using the user-provided Executor below so these callbacks might happen
    // in another thread than we're in right now. For example this happens if using
    // ThreadPoolExecutor.
    //
    // If it turns out that we're going to access shared state we might need locking /
    // synchronization.
    //

    mDataTransport.setListener(new DataTransport.Listener() {
      @Override
      public void onListeningSetupCompleted(@Nullable DataRetrievalAddress address) {
      }

      @Override
      public void onListeningPeerConnecting() {
      }

      @Override
      public void onListeningPeerConnected() {
      }

      @Override
      public void onListeningPeerDisconnected() {
        reportDeviceDisconnected(false);
      }

      @Override
      public void onConnectionResult(@Nullable Throwable error) {
        if (error != null) {
          mDataTransport.close();
          reportError(error);
        } else {
          reportDeviceConnected();
        }
      }

      @Override
      public void onConnectionDisconnected() {
        mDataTransport.close();
        reportError(new IllegalStateException("Error: Disconnected"));
      }

      @Override
      public void onError( Throwable error) {
        mDataTransport.close();
        reportError(error);
        error.printStackTrace();
      }

      @Override
      public void onMessageReceived( byte[] data) {
        if (mSessionEncryptionReader == null) {
          reportError(new IllegalStateException("Message received but no session "
              + "establishment with the remote device."));
          return;
        }

        Pair<byte[], OptionalInt> decryptedMessage = null;
        try {
          decryptedMessage = mSessionEncryptionReader.decryptMessageFromDevice(data);
        } catch (Exception e) {
          mDataTransport.close();
          reportError(new Error("Error decrypting message from device", e));
          return;
        }

        // If there's data in the message, assume it's DeviceResponse (ISO 18013-5
        // currently does not define other kinds of messages).
        //
        if (decryptedMessage.first != null) {
          reportResponseReceived(decryptedMessage.first);
        } else {
          // No data, so status must be set.
          if (!decryptedMessage.second.isPresent()) {
            mDataTransport.close();
            reportError(new Error("No data and no status in SessionData"));
          } else {
            int statusCode = decryptedMessage.second.getAsInt();
            if (statusCode == 20) {
              mDataTransport.close();
              reportDeviceDisconnected(false);
            } else {
              mDataTransport.close();
              reportError(new Error("Expected status code 20, got "
                  + statusCode + " instead"));
            }
          }
        }
      }

      @Override
      public void onTransportSpecificSessionTermination() {
        mDataTransport.close();
        reportDeviceDisconnected(true);
      }

    }, mDeviceResponseListenerExecutor);

    try {
      DataItem deDataItem = TestUtil.cborDecode(mDeviceEngagement);
      DataItem eDeviceKeyBytesDataItem = TestUtil.cborMapExtractArray(deDataItem, 1).get(1);
      byte[] encodedEDeviceKeyBytes = TestUtil.cborEncode(eDeviceKeyBytesDataItem);
      mDataTransport.setEDeviceKeyBytes(encodedEDeviceKeyBytes);
      mDataTransport.connect(address);
    } catch (Exception e) {
      reportError(e);
    }
  }

  void reportDeviceDisconnected(boolean transportSpecificTermination) {
    if (mListener != null) {
      mDeviceResponseListenerExecutor.execute(
          () -> mListener.onDeviceDisconnected(transportSpecificTermination));
    }
  }

  void reportResponseReceived( byte[] deviceResponseBytes) {
    if (mListener != null) {
      mDeviceResponseListenerExecutor.execute(
          () -> mListener.onResponseReceived(deviceResponseBytes));
    }else{
      DeviceResponseParser.DeviceResponse dr = new DeviceResponseParser()
          .setDeviceResponse(deviceResponseBytes)
          .setSessionTranscript(getSessionTranscript())
          .setEphemeralReaderKey(getEphemeralReaderKey())
          .parse();
    }
  }

  void reportMoveIntoNfcField() {
    if (mListener != null) {
      mDeviceResponseListenerExecutor.execute(
          () -> mListener.onMoveIntoNfcField());
    }
  }

  void reportDeviceConnected() {
    if (mListener != null) {
      mDeviceResponseListenerExecutor.execute(
          () -> mListener.onDeviceConnected());
    }
  }

  void reportDeviceEngagementReceived( List<DataRetrievalAddress> addresses) {
    if (mListener != null) {
      mDeviceResponseListenerExecutor.execute(
          () -> mListener.onDeviceEngagementReceived(addresses));
    }
    MdlTest.setAddresses(addresses);
  }

  void reportError(Throwable error) {
    if (mListener != null) {
      mDeviceResponseListenerExecutor.execute(() -> mListener.onError(error));
    }
  }

  public void disconnect() {
    mIsListening = false;
    if (mDataTransport != null) {
      // Only send session termination message if the session was actually established.
      boolean sessionEstablished = (mSessionEncryptionReader.getNumMessagesEncrypted() > 0);
      if (mSendSessionTerminationMessage && sessionEstablished) {
        if (mUseTransportSpecificSessionTermination &&
            mDataTransport.supportsTransportSpecificTerminationMessage()) {
//          Log.d(TAG, "Sending transport-specific termination message");
          mDataTransport.sendTransportSpecificTerminationMessage();
        } else {
//          Log.d(TAG, "Sending generic session termination message");
          byte[] sessionTermination = mSessionEncryptionReader.encryptMessageToDevice(
              null, OptionalInt.of(20));
          mDataTransport.sendMessage(sessionTermination);
        }
      } else {
//        Log.d(TAG, "Not sending session termination message");
      }
//      Log.d(TAG, "Shutting down transport");
      mDataTransport.close();
      mDataTransport = null;
    }
  }

  public void sendRequest( byte[] deviceRequestBytes) {
    if (mDeviceEngagement == null) {
      throw new IllegalStateException("Device engagement is null");
    }
    if (mEphemeralKeyPair == null) {
      throw new IllegalStateException("New object must be created");
    }
    if (mDataTransport == null) {
      throw new IllegalStateException("Not connected to a remote device");
    }

    byte[] message = mSessionEncryptionReader.encryptMessageToDevice(
        deviceRequestBytes, OptionalInt.empty());
//    Log.d(TAG, "sending: " + TestUtil.toHex(message));
    mDataTransport.sendMessage(message);
  }

  public 
  byte[] getSessionTranscript() {
    if (mSessionEncryptionReader == null) {
      throw new IllegalStateException("Not engaging with mdoc device");
    }
    return mSessionEncryptionReader.getSessionTranscript();
  }

  public 
  PrivateKey getEphemeralReaderKey() {
    return mEphemeralKeyPair.getPrivate();
  }

  public void setListener(@Nullable Listener listener,
      @Nullable Executor executor) {
    if (listener != null && executor == null) {
      throw new IllegalStateException("Cannot have non-null listener with null executor");
    }
    mListener = listener;
    mDeviceResponseListenerExecutor = executor;
  }

  public void setUseTransportSpecificSessionTermination(
      boolean useTransportSpecificSessionTermination) {
    mUseTransportSpecificSessionTermination = useTransportSpecificSessionTermination;
  }

  public boolean isTransportSpecificTerminationSupported() {
    if (mDataTransport == null) {
      return false;
    }
    return mDataTransport.supportsTransportSpecificTerminationMessage();
  }

  public void setSendSessionTerminationMessage(
      boolean sendSessionTerminationMessage) {
    mSendSessionTerminationMessage = sendSessionTerminationMessage;
  }

  public interface Listener {

    void onDeviceEngagementReceived( List<DataRetrievalAddress> addresses);

    void onMoveIntoNfcField();

    void onDeviceConnected();

    void onDeviceDisconnected(boolean transportSpecificTermination);

    void onResponseReceived( byte[] deviceResponseBytes);

    void onError( Throwable error);
  }

}
