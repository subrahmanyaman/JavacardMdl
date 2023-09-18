package com.android.jcserver;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;

import com.sun.javacard.apduio.CadTransportException;

public class OracleSimulator implements Simulator {
    private JavaCardHostApp hostApp = new JavaCardHostApp();

    public void initaliseSimulator() throws IOException, CadTransportException {
        hostApp.establishConnectionToSimulator();
        hostApp.powerUp();
    }

    public void disconnectSimulator() throws IOException, CadTransportException {
        hostApp.closeConnection();
        hostApp.powerDown();
    }

    public void setupSimulator(String[] target, String pathToCapFile) {
        try {
            ArrayList<byte[]> scriptApdus = ScriptParser
                    .getApdusFromScript("res/JavaCardKeymaster.scr");
            for (byte[] apdu : scriptApdus) {
                byte[] response = null;
                if ((response = executeApdu(apdu)) != null) {
                    if (!Arrays.equals(response, STATUS_OK)) {
                        System.out.println("Error response from simulator "
                                + Utils.byteArrayToHexString(response));
                        throw new IOException("Error response from simulator"
                                + Utils.byteArrayToHexString(response));
                    }
                } else {
                    throw new IOException("Error in executeApdu");
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        } catch (CadTransportException e) {
            e.printStackTrace();
        }
    }

    public byte[] executeApdu(byte[] apdu) throws IOException, CadTransportException {
        System.out.println("Exeuting apdu " + Utils.byteArrayToHexString(apdu));
        if (hostApp.decodeApduBytes(apdu)) {
            hostApp.exchangeTheAPDUWithSimulator();
            byte[] response = hostApp.decodeStatus();
            System.out.println("Decode status length:" + response.length);
            // for(int i = 0; i < response.length; i++) {
            System.out.print(Utils.byteArrayToHexString(response));
            // }
            System.out.println();
            return response;
        } else {
            System.out.println("Failed to decode APDU [" + Utils.byteArrayToHexString(apdu) + "]");
            return null;
        }
    }

    public byte[] decodeDataOut() {
        return hostApp.decodeDataOut();
    }
}
