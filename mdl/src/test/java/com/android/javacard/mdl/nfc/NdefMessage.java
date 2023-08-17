package com.android.javacard.mdl.nfc;

import java.nio.ByteBuffer;
import java.util.Arrays;

//import org.jetbrains.annotations.Nullable;
public class NdefMessage {
  private final NdefRecord[] mRecords;

  public NdefMessage(byte[] data) throws Exception {
    if (data == null) throw new NullPointerException("data is null");
    ByteBuffer buffer = ByteBuffer.wrap(data);

    mRecords = NdefRecord.parse(buffer, false);

    if (buffer.remaining() > 0) {
      throw new Exception("trailing data");
    }
  }
  public NdefMessage(NdefRecord record, NdefRecord ... records) {
    // validate
    if (record == null) throw new NullPointerException("record cannot be null");

    for (NdefRecord r : records) {
      if (r == null) {
        throw new NullPointerException("record cannot be null");
      }
    }

    mRecords = new NdefRecord[1 + records.length];
    mRecords[0] = record;
    System.arraycopy(records, 0, mRecords, 1, records.length);
  }

  public NdefMessage(NdefRecord[] records) {
    // validate
    if (records.length < 1) {
      throw new IllegalArgumentException("must have at least one record");
    }
    for (NdefRecord r : records) {
      if (r == null) {
        throw new NullPointerException("records cannot contain null");
      }
    }

    mRecords = records;
  }

  public NdefRecord[] getRecords() {
    return mRecords;
  }

  public int getByteArrayLength() {
    int length = 0;
    for (NdefRecord r : mRecords) {
      length += r.getByteLength();
    }
    return length;
  }
  public byte[] toByteArray() {
    int length = getByteArrayLength();
    ByteBuffer buffer = ByteBuffer.allocate(length);

    for (int i=0; i<mRecords.length; i++) {
      boolean mb = (i == 0);  // first record
      boolean me = (i == mRecords.length - 1);  // last record
      mRecords[i].writeToByteBuffer(buffer, mb, me);
    }

    return buffer.array();
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) return true;
    if (obj == null) return false;
    if (getClass() != obj.getClass()) return false;
    NdefMessage other = (NdefMessage) obj;
    return Arrays.equals(mRecords, other.mRecords);
  }

  @Override
  public String toString() {
    return "NdefMessage " + Arrays.toString(mRecords);
  }

  @Override
  public int hashCode() {
    return Arrays.hashCode(mRecords);
  }
}
