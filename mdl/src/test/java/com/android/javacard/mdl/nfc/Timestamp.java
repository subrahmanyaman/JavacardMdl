package com.android.javacard.mdl.nfc;

import androidx.annotation.Nullable;

public final class Timestamp {
  private final long mEpochMillis;

  private Timestamp(long epochMillis) {
    mEpochMillis = epochMillis;
  }

  /**
   * @return a {@code Timestamp} representing the current time
   */
  
  public static Timestamp now() {
    return new Timestamp(System.currentTimeMillis());
  }

  /**
   * @return a {@code Timestamp} representing the given time
   */
  
  public static Timestamp ofEpochMilli(long epochMillis) {
    return new Timestamp(epochMillis);
  }

  /**
   * @return this represented as the number of milliseconds since midnight, January 1, 1970 UTC
   */
  public long toEpochMilli() {
    return mEpochMillis;
  }

  
  @Override
  public String toString() {
    return "Timestamp{epochMillis=" + mEpochMillis + "}";
  }

  @Override
  public boolean equals(Object other) {
    return (other instanceof Timestamp) && ((Timestamp) other).mEpochMillis == mEpochMillis;
  }

  @Override
  public int hashCode() {
    return Long.hashCode(mEpochMillis);
  }
}
