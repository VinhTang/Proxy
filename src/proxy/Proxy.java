/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package proxy;

import ssh.SessionSSH;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.net.Socket;
import java.net.SocketException;
import static proxy.Logs.ClientLog;

/**
 *
 * @author Milky_Way
 */
public class Proxy extends Thread {

    ////////////////////////////////////////////////////////////////////////////
    protected Object bucket;
    protected Thread aThread = null;

    protected SOCKServer SOCKServer = null;

    protected String ProxyHost = null;
    protected int ProxyHostport = 0;

    public SOCKServer getSOCKServer() {
        return SOCKServer;
    }

    public String getProxyHost() {
        return ProxyHost;
    }

    public int getProxyHostport() {
        return ProxyHostport;
    }
    //---------------------------
    public static final int DEFAULT_BUF_SIZE = 4096;

    public Socket ClientSocket = null;
    public Socket ServerSocket = null;

    public int Bufflen = DEFAULT_BUF_SIZE;
    public byte[] Buffer = null;

    public InputStream ClientInput = null;
    public OutputStream ClientOutput = null;
    public InputStream ServerInput = null;
    public OutputStream ServerOutput = null;

    public static final int DEFAULT_TIMEOUT = 10;

    public final boolean Have_Authentication = true; //SOCKs 5 Authentication Method
    ////////////////////////////////////////////////////////////////////////////

    public Proxy(SOCKServer SockServer, Socket ClientSocket, boolean fLog) {

        bucket = this;

        SOCKServer = SockServer;
        if (SOCKServer == null) {
            Close();
            return;
        }
        if (fLog == true) {
            Logs.setLogger(new Logs.ClientLog(ClientSocket));
        }
        this.ClientSocket = ClientSocket;
        if (ClientSocket != null) {
            try {
                ClientSocket.setSoTimeout(DEFAULT_TIMEOUT);
            } catch (SocketException e) {
                Logs.Println(Logger.ERROR, "Socket Exception during seting Timeout.");
            }
        }

        Buffer = new byte[Bufflen];
        
        Logs.Println(Logger.INFO, "Proxy Created!");
    }

    ////////////////////////////////////////////////////////////////////////////
    public void setBucket(Object bucket) {
        this.bucket = bucket;
    }

    ////////////////////////////////////////////////////////////////////////////
    private boolean PrepareClient() {
        if (ClientSocket == null) {
            return false;
        }
        try {
            ClientInput = ClientSocket.getInputStream();
            ClientOutput = ClientSocket.getOutputStream();
        } catch (IOException e) {
            Logs.Println(Logger.ERROR, "Proxy - can't get I/O streams!" + e.toString());

            return false;
        }
        return true;
    }

    ////////////////////////////////////////////////////////////////////////////
    @Override
    public void run() {
        Logs.Println(Logger.INFO, "Proxy start!");

        setBucket(this);
        if (!PrepareClient()) {
            Logs.Println(Logger.ERROR, "Proxy - client socket is null !");
            return;
        }
        ProcessRelay();

    }

    ////////////////////////////////////////////////////////////////////////////
    static final byte SOCK5_version = 0x05;
    static final byte SOCK4_version = 0x04;

    SOCK4 communicator = null;

    private void ProcessRelay() {
        try {
            byte SOCKVersion = GetByteFromClient();

            switch (SOCKVersion) {
                case SOCK4_version:
                    communicator = new SOCK4(this);
                    break;
                case SOCK5_version:
                    communicator = new SOCK5(this);
                    break;
                default:
                    Logs.Println(Logger.ERROR, "Invalid SOKCS version : " + SOCKVersion);
                    return;
            }

            Logs.Println(Logger.INFO, "Accepted SOCKS " + SOCKVersion + " Request.");

            communicator.AuthenticateVersion(SOCKVersion);
            communicator.GetClientCommand();

            Logs.Println(Logger.DEBUG, "ok. ProcessRelay() Proxy.java");

            SessionSSH SSH = new SessionSSH(this);

            //start communication with Server
            switch (communicator.Command) {
                case SOCK4.SC_CONNECT:
                    Logs.Println(Logger.DEBUG, "switch case (communicator)");
                    communicator.Reply_Connect();  // equal Connect()
                    //create SSH Trans
                    SSH.Connect();
            }
        } catch (Exception e) {
        }

    }

    ////////////////////////////////////////////////////////////////////////////
    public byte GetByteFromClient() throws Exception {
        int data;
        while (ClientSocket != null) {
            try {
                data = ClientInput.read();
            } catch (InterruptedIOException ex) {
                Thread.yield();
                continue;

            }
            return (byte) data;
        }
        throw new Exception("Interrupted Reading GetByteFromClient()");
    }

    //----------------------------------------
    public void SendToClient(byte[] Buf) {
        SendToClient(Buf, Buf.length);
    }

    //-----------
    public void SendToClient(byte[] Buf, int Len) {
        if (ClientOutput == null) {
            Logs.Println(Logger.DEBUG, "ClientOutput = null.  SentToCLient() ");
            return;
        }
        if (Len <= 0 || Len > Buf.length) {
            return;
        }

        try {
            ClientOutput.write(Buf, 0, Len);
            ClientOutput.flush();
        } catch (IOException e) {
            Logs.Println(Logger.ERROR, "Sending data to client");
        }
    }

    //----------------------------------------
    ////////////////////////////////////////////////////////////////////////////
    public void Close() {
        //Disconnect Client <-> Proxy
        try {
            if (ClientSocket != null) {
                ClientOutput.flush();
                ClientOutput.close();
                ClientSocket.close();
            }

        } catch (Exception e) {
        }

        //Disconnect Proxy <-> LinuxServer
        try {
            if (ServerSocket != null) {
                ServerOutput.flush();
                ServerOutput.close();
                ServerSocket.close();
            }
        } catch (Exception e) {
        }

        ServerSocket = null;
        ClientSocket = null;

        Logs.Println(Logger.INFO, "Proxy Closed !");
    }
    //-------------------------------------------

    ////////////////////////////////////////////////////////////////////////////
    //---------------------------------------
    public void ConnectToServer(String ServerHost, int ServerPort) throws IOException {
        //	Connect to the Remote Host

        if (ServerHost.equals("")) {
            Close();
            Logs.Println(Logger.ERROR, "Invalid Remote Host Name - Empty String !!!");
            return;
        }

        ServerSocket = new Socket(ServerHost, ServerPort);
        ServerSocket.setSoTimeout(DEFAULT_TIMEOUT);

        Logs.Println(Logger.INFO, "Connected to " + Logs.getSocketInfo(ServerSocket));
        PrepareServer(); // prepare Stream for Server

    }

    //---------------------------------------
    private void PrepareServer() throws IOException {
        synchronized (bucket) {
            ServerInput = ServerSocket.getInputStream();
            ServerOutput = ServerSocket.getOutputStream();
        }
    }
    ////////////////////////////////////////////////////////////////////////////

}
