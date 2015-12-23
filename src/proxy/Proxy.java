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

    protected int HostID = 0;
    protected String UserSSH = null;
    protected String PassSSH = null;

    protected String Username = null;
    protected String Password = null;

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

    //---------------------------
    public static final int DEFAULT_BUF_SIZE = 4096;

    public Socket ClientSocket = null;
    public Socket LinuxSocket = null;

    public InputStream inClient = null;
    public OutputStream outClient = null;
    public InputStream inLinux = null;
    public OutputStream outLinux = null;

    public static final int DEFAULT_TIMEOUT = 15 * 60 * 1000;
    public volatile boolean isConnected = false;

    public final boolean Have_Authentication = true; //SOCKs 5 Authentication Method

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
        this.ClientSocket = ClientSocket;
        if (ClientSocket != null) {
            try {
                ClientSocket.setSoTimeout(DEFAULT_TIMEOUT);
            } catch (SocketException e) {
                Logs.PrintlnProxy(Logger.ERROR, "Socket Exception during seting Timeout.", true);
            }
        }

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
            Logs.PrintlnProxy(Logger.ERROR, "Proxy - can't get I/O streams!" + e.toString(), true);

            return false;
        }
        return true;
    }

    ////////////////////////////////////////////////////////////////////////////
    @Override
    public void run() {

        setBucket(this);
        isConnected = true;
        SOCKServer.addSession(this);

        Logger ClientLog = new Logs.ClientLog(ClientSocket);
        Logs.setClientLog(ClientLog);
        
        if (!PrepareClient()) {
            Logs.PrintlnProxy(Logger.ERROR, "Proxy - client socket is null !", true);
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
                    Logs.PrintlnProxy(Logger.ERROR, "Invalid SOKCS version : " + SOCKVersion, true);
                    ClientSocket.close();
                    return;
            }

            if (communicator.AuthenticateVersion(SOCKVersion) == false) {
                ClientSocket.close();
            }
            communicator.GetClientCommand();

            Username = communicator.getUsername();
            Password = communicator.getPassword();
            RemoteHost = communicator.getRemoteHost();
            RemotePort = communicator.getRemotePort();
            //-------------------------------------------------------

            Logs.setLogUsers();
            if (DB_controller.CheckUser(this, Username, Password, RemoteHost) == true) {
                Logs.PrintlnProxy(Logger.INFO, "User:" + Username + "; version:SOCKv" + SOCKVersion + ";type:success.", false);
                Logs.Println(Logger.INFO, "User:" + Username + "; version:SOCKv" + SOCKVersion + ";type:success.", false);
            } else {
                System.err.println("vao");
                Logs.PrintlnProxy(Logger.INFO, "User:" + Username + "; version:SOCKv" + SOCKVersion + ";type:Fail.", false);
                Logs.Println(Logger.INFO, "User:" + Username + "; version:SOCKv" + SOCKVersion + ";type:Fail.", false);
                this.Close();
                return;
            };

            Logs.Println(Logger.INFO, "Accepted SOCKS " + SOCKVersion + " Request! ", true);
            //---------SSH CONNECT-------------------------------------

            if (ConnectToServer(RemoteHost, RemotePort) == false) {
                this.Close();
            }
            //System.out.println(" USer name :"+ Username + " Pass "+ Password);
            ServerSide = new sshServer(this);
            LinuxSide = new sshLinux(this, RemoteHost);
            LinuxSide.setUserName(UserSSH);
            LinuxSide.setPassword(PassSSH);

            //start communication with sshServer
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
                        Logs.PrintlnProxy(Logger.INFO, "User:" + Username + "; version:SSH; msg:Created ServerSide; type:Success.", false);
                        Logs.Println(Logger.INFO, "User:" + Username + "; version:SSH; msg:Created ServerSide; type:Success.", false);
                        linux = LinuxSide.connect();
                        while (linux == false) {
                        }
                        Logs.PrintlnProxy(Logger.INFO, "User:" + Username + "; version:SSH; HostID:" + HostID
                                + "; msg:Created LinuxSide; type:Success.", false);
                        Logs.Println(Logger.INFO, "User:" + Username + "; version:SSH; HostID:" + HostID
                                + "; msg:Created LinuxSide; type:Success.", false);
                    }
            }

            if (server == true && linux == true) {
                Relay();

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
            return;
        }
        if (Len <= 0 || Len > Buf.length) {
            return;
        }

        try {
            outClient.write(Buf, 0, Len);
            outClient.flush();
        } catch (IOException e) {
        }
    }

    ////////////////////////////////////////////////////////////////////////////
    public void Close() {

        if (isConnected == false) {
            return;
        }
        Logs.PrintlnProxy(Logger.INFO, "username:" + Username + "; version:; msg: Diconnect host; " + "HostID:" + HostID, false);

        isConnected = false;
        try {

            if (LinuxSide != null) {
                LinuxSide.disconnectpacket("");
                LinuxSide.disconnect();
            }
            if (ServerSide != null) {
                ServerSide.disconnectpacket("");
                ServerSide.disconnect();
            }
        } catch (Exception e) {
        }
        Logs.Println(Logger.INFO, "username:" + Username + "; version:; msg: Diconnect host; " + "HostID:" + HostID, false);
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
        SOCKServer.removeSession(this);
        Logs.PrintlnProxy(Logger.INFO, "Username:" + Username + "; version:; msg:User Discconnect!.", false);
        Logs.Println(Logger.INFO, "Username:" + Username + "; version:; msg:User Discconnect!.", false);
    }
    //-------------------------------------------

    //////////////////////////////////////////////////////////////////////////
    public boolean ConnectToServer(String Remotehost, int remoteport) {
        //	Connect to the Remote Host

        if (Remotehost.equals("")) {
            Close();
            Logs.Println(Logger.ERROR, "Invalid Remote Host Name - Empty String !!!", true);
            return false;
        }
        try {
            LinuxSocket = new Socket(Remotehost, remoteport);
            return true;
        } catch (Exception e) {
            Logs.Println(Logger.ERROR, "Remotehost " + Remotehost + " is not available. Connect close", true);
            Logs.PrintlnProxy(Logger.INFO, "Remotehost " + Remotehost + " is not available. Connect close", true);
            return false;
        }
    }
}
    //---------------------------------------
    /////////////////////////////////////////////////////////////
