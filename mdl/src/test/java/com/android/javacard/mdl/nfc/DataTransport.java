package com.android.javacard.mdl.nfc;

import static java.nio.charset.StandardCharsets.UTF_8;

import androidx.annotation.Nullable;
import com.esotericsoftware.kryo.serializers.FieldSerializer.NotNull;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Executor;

import co.nstant.in.cbor.model.Array;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.Number;


abstract class DataTransport {
  private static final String TAG = "DataTransport";
  boolean mInhibitCallbacks;
  private @Nullable
  Listener mListener;
  private @Nullable
  Executor mListenerExecutor;
  private @Nullable
  Executor mProgressListenerExecutor;

  DataTransport() {

  }

  static @Nullable
  List<DataRetrievalAddress> parseDeviceRetrievalMethod(
      byte[] encodedDeviceRetrievalMethod) {

    DataItem d = TestUtil.cborDecode(encodedDeviceRetrievalMethod);
    if (!(d instanceof Array)) {
      throw new IllegalArgumentException("Given CBOR is not an array");
    }
    DataItem[] items = ((Array) d).getDataItems().toArray(new DataItem[0]);
    if (items.length < 2) {
      throw new IllegalArgumentException("Expected two elems or more, got " + items.length);
    }
    if (!(items[0] instanceof Number) || !(items[1] instanceof Number)) {
      throw new IllegalArgumentException("Items not of required type");
    }
    int type = ((Number) items[0]).getValue().intValue();
    int version = ((Number) items[1]).getValue().intValue();

    switch (type) {
      case DataTransportNfc.DEVICE_RETRIEVAL_METHOD_TYPE:
        return DataTransportNfc.parseDeviceRetrievalMethod(version, items);
      default:
        return null;
    }
  }

  /**
   * Returns a list of addresses (typically one) inferred from parsing an NDEF record.
   *
   * @param record an NDEF record.
   * @return List of {@link DataRetrievalAddress} or <code>null</code> if none were found.
   */
  static @Nullable
  List<DataRetrievalAddress> parseNdefRecord(
      NdefRecord record) {

    // NFC Carrier Configuration record
    //
    if (record.getTnf() == 0x02
        && Arrays.equals(record.getType(),
        "iso.org:18013:nfc".getBytes(UTF_8))
        && Arrays.equals(record.getId(), "nfc".getBytes(UTF_8))) {
      return DataTransportNfc.parseNdefRecord(record);
    }
    return null;
  }

  /**
   * Sets the bytes of <code>EDeviceKeyBytes</code>.
   *
   * <p>This is required for some transports, for example BLE. Listeners (e.g. mdoc apps) will
   * pass the value they generate and initiators (e.g. mdoc reader apps) will pass the value
   * they receive through device engagement.
   *
   * <p>This should be called before calling {@link #listen()} or
   * {@link #connect(DataRetrievalAddress)}.
   *
   * @param encodedEDeviceKeyBytes bytes of <code>EDeviceKeyBytes</code> CBOR.
   */
  abstract void setEDeviceKeyBytes(byte[] encodedEDeviceKeyBytes);

  /**
   * Connects to the mdoc.
   *
   * <p>This is an asynchronous operation, {@link Listener#onConnectionResult(Throwable)}
   * is called with whether the connection attempt worked.
   *
   * @param address a {@link DataRetrievalAddress}.
   * @throws IllegalArgumentException if the given address is malformed.
   */
  abstract void connect(DataRetrievalAddress address);

  /**
   * Starts listening on the transport.
   *
   * Parameters that may vary (e.g. port number) are chosen by the implementation or informed
   * by the caller out-of-band using e.g. transport-specific setters. All details are returned
   * as part of the <code>DeviceRetrievalMethod</code> CBOR returned.
   *
   * <p>This is an asynchronous operation. When listening has been set up the
   * {@link Listener#onListeningSetupCompleted(DataRetrievalAddress)} method is called with
   * address the listener is listening to or <code>null</code> if the operation fails. When a
   * peer connects {@link Listener#onListeningPeerConnected()} is called. Only a single peer
   * will be allowed to connect. When the peer disconnects
   * {@link Listener#onListeningPeerDisconnected()} is called.
   */
  abstract void listen();

  /**
   * Gets the address that can be used to connecting to the listening transport.
   *
   * <p>This is the same address which is returned by the
   * {@link Listener#onListeningSetupCompleted(DataRetrievalAddress)} callback.
   *
   * @return A {@link DataRetrievalAddress}.
   */
  abstract DataRetrievalAddress getListeningAddress();

  /**
   * If this is a listening transport, stops listening and disconnects any peer already
   * connected. If it's a connecting transport, disconnects the active peer. If no peer is
   * connected, does nothing.
   *
   * <p>Messages previously sent with {@link #sendMessage(byte[])} will be sent before the
   * connection is closed.
   * TODO: actually implement this guarantee for all transports.
   *
   * <p>After calling this method, no more callbacks will be delivered.
   */
  abstract void close();

  /**
   * Sends data to the remote peer.
   *
   * <p>This is an asynchronous operation, data will be sent by another thread. It's safe to
   * call this right after {@link #connect(DataRetrievalAddress)}, data will be queued up and
   * sent once a connection has been established.
   *
   * @param data the data to send
   */
  abstract void sendMessage(byte[] data);

  /**
   * Send data to the remote peer and listen for progress updates.
   *
   * @param data the data to send
   * @param progressListenerExecutor a {@link Executor} to do the progress listener updates in or
   *                                 <code>null</code> if <code>listener</code> is
   *                                 <code>null</code>.
   */
  void sendMessage(byte[] data, @Nullable Executor progressListenerExecutor) {
    this.mProgressListenerExecutor = progressListenerExecutor;
    sendMessage(data);
  }

  /**
   * Sends a transport-specific termination message.
   *
   * This may not be supported by the transport, use
   * {@link #supportsTransportSpecificTerminationMessage()} to find out.
   */
  abstract void sendTransportSpecificTerminationMessage();

  /**
   * Whether the transport supports a transport-specific termination message.
   *
   * Only known transport to support this is BLE.
   *
   * @return {@code true} if supported, {@code false} otherwise.
   */
  abstract boolean supportsTransportSpecificTerminationMessage();

  /**
   * Set the listener to be used for notification.
   *
   * <p>This may be called multiple times but only one listener is active at one time.
   *
   * @param listener the listener or <code>null</code> to stop listening.
   * @param executor a {@link Executor} to do the call in or <code>null</code> if
   *                 <code>listener</code> is <code>null</code>.
   * @throws IllegalStateException if {@link Executor} is {@code null} for a non-{@code null}
   * listener.
   */
  void setListener(@Nullable Listener listener, @Nullable Executor executor) {
    if (listener != null && executor == null) {
//      throw new IllegalStateException("Passing null Executor for non-null Listener");
    }
    mListener = listener;
    mListenerExecutor = executor;
  }

  // Should be called by close() in subclasses to signal that no callbacks should be made
  // from here on.
  //
  protected void inhibitCallbacks() {
    mInhibitCallbacks = true;
  }

  // Note: The report*() methods are safe to call from any thread.

  protected void reportListeningSetupCompleted(@Nullable DataRetrievalAddress address) {
    final Listener listener = mListener;
    final Executor executor = mListenerExecutor;
    if (!mInhibitCallbacks && listener != null && executor != null) {
      executor.execute(() -> listener.onListeningSetupCompleted(address));
    }else{
      listener.onListeningSetupCompleted(address);
    }
  }

  protected void reportListeningPeerConnecting() {
    final Listener listener = mListener;
    final Executor executor = mListenerExecutor;
    if (!mInhibitCallbacks && listener != null && executor != null) {
      executor.execute(listener::onListeningPeerConnecting);
    }else{
      listener.onListeningPeerConnecting();
    }
  }

  protected void reportListeningPeerConnected() {
    final Listener listener = mListener;
    final Executor executor = mListenerExecutor;
    if (!mInhibitCallbacks && listener != null && executor != null) {
      executor.execute(listener::onListeningPeerConnected);
    }else{
      listener.onListeningPeerConnected();
    }
  }

  protected void reportListeningPeerDisconnected() {
    final Listener listener = mListener;
    final Executor executor = mListenerExecutor;
    if (!mInhibitCallbacks && listener != null && executor != null) {
      executor.execute(listener::onListeningPeerDisconnected);
    }else{
      listener.onListeningPeerDisconnected();
    }
  }

  protected void reportConnectionResult(@Nullable Throwable error) {
    final Listener listener = mListener;
    final Executor executor = mListenerExecutor;
    if (!mInhibitCallbacks && listener != null && executor != null) {
      executor.execute(() -> listener.onConnectionResult(error));
    }else{
      listener.onConnectionResult(error);
    }
  }

  protected void reportConnectionDisconnected() {
    final Listener listener = mListener;
    final Executor executor = mListenerExecutor;
    if (!mInhibitCallbacks && listener != null && executor != null) {
      executor.execute(listener::onConnectionDisconnected);
    }else{
      listener.onConnectionDisconnected();
    }
  }

  protected void reportMessageReceived(byte[] data) {
    final Listener listener = mListener;
    final Executor executor = mListenerExecutor;
    if (!mInhibitCallbacks && listener != null && executor != null) {
      executor.execute(() -> listener.onMessageReceived(data));
    }else{
      listener.onMessageReceived(data);
    }
  }

  protected void reportMessageProgress(long progress, long max) {
    /*
    final TransmissionProgressListener listener = mProgressListener;
    final Executor executor = mProgressListenerExecutor;
    if (!mInhibitCallbacks && listener != null && executor != null) {
      executor.execute(() -> listener.onProgressUpdate(progress, max));
    }
     */

  }

  protected void reportTransportSpecificSessionTermination() {
    final Listener listener = mListener;
    final Executor executor = mListenerExecutor;
    if (!mInhibitCallbacks && listener != null && executor != null) {
      executor.execute(listener::onTransportSpecificSessionTermination);
    }else{
      listener.onTransportSpecificSessionTermination();
    }
  }

  protected void reportError(Throwable error) {
    final Listener listener = mListener;
    final Executor executor = mListenerExecutor;
    if (!mInhibitCallbacks && listener != null && executor != null) {
      executor.execute(() -> listener.onError(error));
    }else {
      listener.onError(error);
    }
  }

  /**
   * Interface for listener.
   */
  interface Listener {

    /**
     * Called on a listening transport when listening setup has completed and
     * an address for how to connect is ready.
     */
    void onListeningSetupCompleted(@Nullable DataRetrievalAddress address);

    /**
     * Called when a listening transport first sees a new connection.
     *
     * <p>Depending on the transport in use it could be several seconds until
     * {@link #onListeningPeerConnected()} is called.
     */
    void onListeningPeerConnecting();

    /**
     * Called when a listening transport has accepted a new connection.
     */
    void onListeningPeerConnected();

    /**
     * Called when the peer which connected to a listening transport disconnects.
     *
     * <p>If this is called, the transport can no longer be used and the caller
     * should call {@link DataTransport#close()} to release resources.
     */
    void onListeningPeerDisconnected();

    /**
     * Called when the connection started with {@link #connect(DataRetrievalAddress)} succeeds.
     *
     * <p>If the connection didn't succeed, the transport can no longer be used and the caller
     * should call {@link DataTransport#close()} to release resources.
     *
     * @param error if the connection succeeded, this is <code>null</code>, otherwise
     *              details about what failed
     */
    void onConnectionResult(@Nullable Throwable error);

    /**
     * Called when the connection established with {@link #connect(DataRetrievalAddress)} has
     * been disconnected.
     *
     * <p>If this is called, the transport can no longer be used and the caller
     * should call {@link DataTransport#close()} to release resources.
     */
    void onConnectionDisconnected();

    /**
     * Called when receiving data from the peer.
     *
     * @param data the received data.
     */
    void onMessageReceived(byte[] data);

    /**
     * Called when receiving a transport-specific session termination request.
     *
     * <p>Only known transport to support this is BLE.
     */
    void onTransportSpecificSessionTermination();

    /**
     * Called if the transports encounters an unrecoverable error.
     *
     * <p>If this is called, the transport can no longer be used and the caller
     * should call {@link DataTransport#close()} to release resources.
     *
     * @param error the error that occurred.
     */
    void onError(Throwable error);
  }

}


