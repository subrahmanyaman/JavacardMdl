package com.android.javacard.mdl.nfc;

import static java.lang.annotation.RetentionPolicy.SOURCE;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;

@Retention(SOURCE)
@Target(ElementType.ANNOTATION_TYPE)
public @interface LongDef {
  /**
   * Defines the allowed constants for this element
   */
  long[] value();
  /**
   * Defines whether the constants can be used as a flag, or just as an enum (the default)
   */
  boolean flag() default false;
  /**
   * Whether any other values are allowed. Normally this is not the case, but this allows you to
   * specify a set of expected constants, which helps code completion in the IDE and documentation
   * generation and so on, but without flagging compilation warnings if other values are specified.
   */
  boolean open()  default false;
}
