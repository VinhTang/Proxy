/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package proxy;

import SSHServer.sshLinux;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.net.Socket;
import java.net.SocketException;
import SSHServer.sshServer;
import java.util.Queue;

/**
 *
 * @author Milky_Way
 */
public class Proxy extends Thread {

    ////////////////////////////////////////////////////////////////////////////
    protected Object bucket;
    protected Thread aThread = null;

    protected SOCKServer SOCKServer = null;

    protected String RemoteHost = null;
    protected int RemotePort = 0;

    protected String Host = null;
    protected int HostPort = 0;

    protected String UserSSH = "vinh";
    protected String PassSSH = "123";

    ////////////////////////////////////////////////////////////////////////////
    //get Method
    public String getRemoteHost() {
        return RemoteHost;
    }

    public int getRemotePort() {
        return RemotePort;
    }

    public String getHost() {
        return Host;
    }

    public int getPort() {
        return HostPort;
    }

    // set Method
    public void setRemoteHost(String Rhost) {
        this.RemoteHost = Rhost;
    }

    public void setRemotePort(int RPort) {
        this.RemotePort = RPort;
    }

    public void setHost(String Host) {
        this.Host = Host;
    }

    public void setPort(int Hport) {
        this.HostPort = Hport;
    }
    //---------------------------
    public static final int DEFAULT_BUF_SIZE = 4096;

    public Socket ClientSocket = null;
    public Socket LinuxSocket = null;

    public InputStream inClient = null;
    public OutputStream outClient = null;
    public InputStream inLinux = null;
    public OutputStream outLinux = null;

    public static final int DEFAULT_TIMEOUT = 3 * 60 * 1000;
    public volatile boolean isConnected = false;

    public final boolean Have_Authentication = false; //SOCKs 5 Authentication Method

    public Proxy getProxy() {
        return this;
    }

    public static volatile Queue queue;

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
            inClient = ClientSocket.getInputStream();
            outClient = ClientSocket.getOutputStream();
        } catch (IOException e) {
            Logs.Println(Logger.ERROR, "Proxy - can't get I/O streams!" + e.toString());

            return false;
        }
        return true;
    }

    ////////////////////////////////////////////////////////////////////////////
    @Override
    public void run() {

        setBucket(this);
        SOCKServer.addSession(this);
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
            // ---------SOCK CONNECT---------------------------------
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
            communicator.AuthenticateVersion(SOCKVersion);
            communicator.GetClientCommand();
            //-------------------------------------------------------
            Logs.Println(Logger.INFO, "Accepted SOCKS " + SOCKVersion + " Request! ");

            //---------SSH CONNECT-------------------------------------
            RemoteHost = communicator.getRemoteHost();
            RemotePort = communicator.getRemotePort();
            // sshserver check username/pass ? setRemotehost, of Proxy class : disconnect in sshserver
            if (ConnectToServer(RemoteHost, RemotePort) == false) {
                this.Close();
            }

            ServerSide = new sshServer(this);
            LinuxSide = new sshLinux(this, UserSSH, RemoteHost);
            //start communication with sshServer
            isConnected = true;
            boolean server = false;
            boolean linux = false;
            switch (communicator.Command) {
                case SOCK4.SC_CONNECT:
                    communicator.Reply_Connect();  // equal Connect()
                    //create SSH Trans
                    synchronized (bucket) {
                        server = ServerSide.Connect();
                        while (server == false) {

                        }
                        linux = LinuxSide.connect();
                        while (linux == false) {
                        }
                    }
            }

            while (true) {
                if (server == true && linux == true) {
                    Relay();
                    break;
                }
            }
        } catch (Exception e) {
        }

    }

    ////////////////////////////////////////////////////////////////////////////
    private SSHServer.sshServer ServerSide;
    private SSHServer.sshLinux LinuxSide;

    public void Relay() throws Exception {
        ClienttoServer CtoS = new ClienttoServer(this, ServerSide, LinuxSide);
        ServertoLinux StoL = new ServertoLinux(this, ServerSide, LinuxSide);
//        Thread CtoS = new Thread(new ClienttoServer(bucket, ServerSide, LinuxSide), "Clien to Server");
//        Thread StoL = new Thread(new ServertoLinux(bucket, ServerSide, LinuxSide), "Server to Linux");
        CtoS.start();
        StoL.start();
        
    }

////////////////////////////////////////////////////////////////////////////
    public byte GetByteFromClient() throws Exception {
        int data;
        while (ClientSocket != null) {
            try {
                data = inClient.read();

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
        if (outClient == null) {
            Logs.Println(Logger.DEBUG, "outClient = null.  SentToCLient() ");
            return;
        }
        if (Len <= 0 || Len > Buf.length) {
            return;
        }

        try {
            outClient.write(Buf, 0, Len);
            outClient.flush();
        } catch (IOException e) {
            Logs.Println(Logger.ERROR, "Sending data to client");
        }
    }

    ////////////////////////////////////////////////////////////////////////////
    public void Close() {

        if (isConnected == false) {
            return;
        }
        if (Logs.getLogger().isEnabled(proxy.Logger.INFO)) {
            Logs.Println(proxy.Logger.INFO,
                    "Disconnecting from " + RemoteHost + " port " + RemotePort);
        }
        isConnected = false;
        try {

            if (LinuxSide != null) {
                LinuxSide.disconnectpacket("");
                LinuxSide.disconnect();
            }
            if (ServerSide != null) {
                ServerSide.disconnectpacket("");
                LinuxSide.disconnect();
            }
        } catch (Exception e) {
        }
        //Disconnect Proxy <-> Linux
        try {
            if (LinuxSocket != null) {
                LinuxSocket.shutdownInput();
                LinuxSocket.shutdownOutput();
                LinuxSocket.close();
            }
        } catch (Exception e) {
        }

        //  Disconnect Client <-> Proxy
        try {
            if (ClientSocket != null) {
                ClientSocket.shutdownInput();
                ClientSocket.shutdownOutput();
                ClientSocket.close();
            }
        } catch (Exception e) {
        }
        LinuxSocket = null;
        ClientSocket = null;

        Logs.PrintlnProxy(Logger.INFO, "Connecttion from user " + Tools.byte2str(communicator.UserID)+ " close!");
    }
    //-------------------------------------------

    //////////////////////////////////////////////////////////////////////////
    public boolean ConnectToServer(String Remotehost, int remoteport) {
        //	Connect to the Remote Host

        if (Remotehost.equals("")) {
            Close();
            Logs.Println(Logger.ERROR, "Invalid Remote Host Name - Empty String !!!");
            return false;
        }
        try {
            LinuxSocket = new Socket(Remotehost, remoteport);
            return true;
        } catch (Exception e) {
            Logs.Println(Logger.ERROR, "Remotehost " + Remotehost + " is not available. Connect close");
            Logs.PrintlnProxy(Logger.INFO, "Remotehost " + Remotehost + " is not available. Connect close");
            return false;
        }
    }
}
    //---------------------------------------
    /////////////////////////////////////////////////////////////
