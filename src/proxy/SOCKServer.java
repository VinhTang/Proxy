package proxy;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

public class SOCKServer extends Thread {

    public static final int LISTEN_TIMEOUT = 200;
    public static final int DEFAULT_TIMEOUT = 200;

    protected Object Bucket;
    //protected Thread theThread = null;
    protected ServerSocket ListenSocket = null;
    protected int listenPort = 0;


    ////////////////////////////////////////////////////////////////////////////
    public int getPort() {
        return listenPort;
    }

    ////////////////////////////////////////////////////////////////////////////
    SOCKServer(int listen_Port) {
        this.Bucket = this;
        listenPort = listen_Port;

    }

    ////////////////////////////////////////////////////////////////////////////
    private void SetBucket(Object bucket) {
        this.Bucket = bucket;
    }
    ////////////////////////////////////////////////////////////////////////////

    public void run() {
        Logs.PrintlnProxy(Logger.INFO, "SOCKS Server Start Listen !");
        SetBucket(this);
        Listen();

    }
    ////////////////////////////////////////////////////////////////////////////

    protected void Listen() {
        try {
            PrepareToListen();
        } catch (java.net.BindException e) {
            Logs.PrintlnProxy(Logger.ERROR, "The Port " + listenPort + " is in use !" + e);
            return;
        } catch (IOException e) {
            Logs.PrintlnProxy(Logger.ERROR, "IO Error Binding at port : " + listenPort + e);
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
            Logs.PrintlnProxy(Logger.INFO, "SOCKS SERVER Listen at Port: " + listenPort);
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

                Logs.PrintlnProxy(Logger.INFO, "Connection from: " + Logs.getSocketInfo(ClientSocket));
                Proxy proxy = null;
                if (SSHProxy.ClientLog == true) {
                    proxy = new Proxy(this, ClientSocket, true);
                } else {
                    proxy = new Proxy(this, ClientSocket, false);
                }
                proxy.start();

            } catch (Exception e) {

            }
        }
    }
    ////////////////////////////////////////////////////////////////////////////

}
