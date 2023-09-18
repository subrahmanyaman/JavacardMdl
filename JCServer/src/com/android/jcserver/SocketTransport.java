package com.android.jcserver;

import java.net.*;
import java.io.*;
import java.util.ArrayList;
import java.util.List;




public class SocketTransport {
    private static final int PORT = 8080;
    private static final String IPADDR = "192.168.9.112";
    private static final int MAX_RECV_BUFFER_SIZE = 2500;
    
    private Socket mSocket;
    private boolean socketStatus;
    
    public boolean openConnection() {
        try {
            InetAddress serverAddress = InetAddress.getByName(IPADDR);
            mSocket = new Socket(serverAddress, PORT);
            socketStatus = true;
            return true;
        } catch (IOException e) {
            System.out.println("SocketTransport Socket creation failed. Error: " + e.getMessage());
            return false;
        }
    }
    
    public boolean sendData(List<Byte> inData, List<Byte> output) {
        int count = 1;
        while (!socketStatus && count++ < 5) {
            try {
                Thread.sleep(1000);
                System.out.println("SocketTransport Trying to open socket connection... count: " + count);
                openConnection();
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }

        if (count >= 5) {
        	System.out.println("SocketTransport Failed to open socket connection");
            return false;
        }

        // Prepend the input length to the inputData before sending.
        List<Byte> inDataPrependedLength = new ArrayList<>();
        inDataPrependedLength.add((byte) (inData.size() >> 8));
        inDataPrependedLength.add((byte) (inData.size() & 0xFF));
        inDataPrependedLength.addAll(inData);

        try {
            OutputStream outputStream = mSocket.getOutputStream();
            outputStream.write(convertListToArray(inDataPrependedLength));
            outputStream.flush();
        } catch (IOException e) {
        	System.out.println("SocketTransport Failed to send data over socket. Error: " + e.getMessage());
            return false;
        }

        if (!readData(output)) {
            return false;
        }
        return true;
    }
    
    public boolean closeConnection() {
        try {
            mSocket.close();
            socketStatus = false;
            return true;
        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }
    }
    
    public boolean isConnected() {
        return socketStatus;
    }
    
    private boolean readData(List<Byte> output) {
        byte[] buffer = new byte[MAX_RECV_BUFFER_SIZE];
        int expectedResponseLen = 0;
        int totalBytesRead = 0;

        try {
            InputStream inputStream = mSocket.getInputStream();
            while (totalBytesRead < expectedResponseLen) {
                int numBytes = inputStream.read(buffer, 0, MAX_RECV_BUFFER_SIZE);
                if (numBytes < 0) {
                	System.out.println("SocketTransport Failed to read data from socket.");
                    return false;
                }
                totalBytesRead += numBytes;
                if (expectedResponseLen == 0) {
                    expectedResponseLen |= (buffer[1] & 0xFF);
                    expectedResponseLen |= ((buffer[0] << 8) & 0xFF00);
                    expectedResponseLen += 2;
                }
                for (int i = 2; i < numBytes; i++) {
                    output.add(buffer[i]);
                }
            }
            return true;
        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }
    }

    private byte[] convertListToArray(List<Byte> list) {
        byte[] array = new byte[list.size()];
        for (int i = 0; i < list.size(); i++) {
            array[i] = list.get(i);
        }
        return array;
    }


}
