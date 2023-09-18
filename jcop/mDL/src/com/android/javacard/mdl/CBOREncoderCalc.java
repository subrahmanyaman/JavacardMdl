package com.android.javacard.mdl;

import com.android.javacard.mdl.CBORBase;
import com.android.javacard.mdl.CBOREncoder;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

/**
 * This class extends encoder and it is used to calculate the total size required for encoded
 * stream. This is used for cases where size of encoded stream is required before the actual
 * encoding is done in the future.
 */
public class CBOREncoderCalc extends CBOREncoder {

  /**
   * Increase the offset by one.
   */
  short writeRawByte(byte val) {
    increaseOffset((short) 1);
    return (short) 1;
  }

  /**
   *  Increase the offset by two.
   */
  short writeRawShort(short val) {
    increaseOffset((short) 2);
    return (short) 2;
  }

  /**
   * Increase the offset by its size.
   *
   * @param value  Buffer array with the content
   * @param offset Offset in input buffer
   * @param length Length of data that should be encoded
   * @return The current offset in the buffer
   */
  short writeRawByteArray(byte[] value, short offset, short length) {
    increaseOffset(length);
    return length;
  }
}
