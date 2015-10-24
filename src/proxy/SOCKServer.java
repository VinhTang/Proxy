package proxy;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
/**
 *
 * @author Milky_Way
 */
public class SOCKServer extends Thread {

    public static final int LISTEN_TIMEOUT = 200;
    public static final int DEFAULT_TIMEOUT = 200;

    protected Object Bucket;
    //protected Thread theThread = null;
    protected ServerSocket ListenSocket = null;
    protected int listenPort = 0;

//    protected String ProxyHost = null;
//    protected int ProxyHostport = 0;

    ////////////////////////////////////////////////////////////////////////////
    public int getPort() {
        return listenPort;
    }

    ////////////////////////////////////////////////////////////////////////////
    public SOCKServer(int listen_Port) {
        this.Bucket = this;
        listenPort = listen_Port;


        Logs.Println("SOCKS Server Created. ");

    }

    ////////////////////////////////////////////////////////////////////////////
    private void SetBucket(Object bucket) {
        this.Bucket = bucket;
    }
    ////////////////////////////////////////////////////////////////////////////

    @Override
    public void run() {
        SetBucket(this);
        Listen();

    }
    ////////////////////////////////////////////////////////////////////////////

    protected void Listen() {
        try {
            PrepareToListen();
        } catch (java.net.BindException e) {
            Logs.Error("The Port " + listenPort + " is in use !");
            Logs.Error(e);
            return;
        } catch (IOException e) {
            Logs.Error("IO Error Binding at port : " + listenPort);
            return;
        }
        while (isActive()) {
            CheckClientConnection();
            Thread.yield();
        }
    }

    private void PrepareToListen() throws IOException {
        synchronized (Bucket) {
            //start Socket listen request from client
            ListenSocket = new ServerSocket(listenPort);
            ListenSocket.setSoTimeout(LISTEN_TIMEOUT);

            if (listenPort == 0) {
                listenPort = ListenSocket.getLocalPort();
            }
            Logs.Println("SOCKS SERVER Listen at Port: " + listenPort);
        }
    }
    ////////////////////////////////////////////////////////////////////////////

    public boolean isActive() {
        if (ListenSocket != null) {
            return true;
        } else {
            return false;
        }
    }

    ////////////////////////////////////////////////////////////////////////////
    private void CheckClientConnection() {
        synchronized (Bucket) {
            if (isActive() == false) {
                return;
            }
            try {
                Socket ClientSocket = ListenSocket.accept();
                ClientSocket.setSoTimeout(DEFAULT_TIMEOUT);

                Logs.Println("Connection from: " + Logs.getSocketInfo(ClientSocket));
                Proxy proxy = new Proxy(this, ClientSocket);
                proxy.start();

            } catch (Exception e) {
            }
        }
    }
    ////////////////////////////////////////////////////////////////////////////
}
