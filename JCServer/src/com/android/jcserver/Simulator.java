package com.android.jcserver;

public interface Simulator {
    byte[] STATUS_OK = Utils.hexStringToByteArray("9000");

    void initaliseSimulator() throws Exception;

    void disconnectSimulator() throws Exception;

    void setupSimulator(String[] target, String capFilePath) throws Exception;

    byte[] executeApdu(byte[] apdu) throws Exception;

    byte[] decodeDataOut();
}
