package com.android.javacard.mdl.nfc;
import java.util.List;

import co.nstant.in.cbor.CborBuilder;
import co.nstant.in.cbor.builder.ArrayBuilder;

abstract public class DataRetrievalAddress {
  DataRetrievalAddress() {
  }

  abstract
  DataTransport createDataTransport();

  abstract void addDeviceRetrievalMethodsEntry(ArrayBuilder<CborBuilder> arrayBuilder,
      List<DataRetrievalAddress> listeningAddresses);

  abstract Pair<NdefRecord, byte[]> createNdefRecords(
      List<DataRetrievalAddress> listeningAddresses);
}
