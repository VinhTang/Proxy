/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package proxy;

import SSHClient.JSch;
import SSHClient.JSchException;

import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.net.Socket;
import java.net.SocketException;
import SSHServer.SessionSSH;
import java.util.LinkedList;
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

    public static Socket ClientSocket = null;
    public static Socket ServerSocket = null;

    public int Bufflen = DEFAULT_BUF_SIZE;
    public InputStream ClientInput = null;
    public OutputStream ClientOutput = null;

    public static final int DEFAULT_TIMEOUT = 3 * 60 * 1000;

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
        queue = new LinkedList();

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

            RemoteHost = communicator.getRemoteHost();
            RemotePort = communicator.getRemotePort();
            // sshserver check username/pass ? setRemotehost, of Proxy class : disconnect in sshserver

            Logs.Println(Logger.DEBUG, "ok. ProcessRelay() Proxy.java");

            ServerSide = new SessionSSH(this);

            //start communication with Server
            switch (communicator.Command) {
                case SOCK4.SC_CONNECT:
                    communicator.Reply_Connect();  // equal Connect()
                    //create SSH Trans

                    ServerSide.Connect();
                    createClientSide();

                    Relay();
            }
        } catch (Exception e) {
        }

    }

    ////////////////////////////////////////////////////////////////////////////
    private SSHServer.SessionSSH ServerSide;
    private SSHServer.Channel channelServer;

    private SSHClient.JSch ClientSide;
    private SSHClient.Session session;
    private SSHClient.Channel channelClient;
    public static byte[] data;

    //---------------------------------
//    public void intData(int size) {
//        data = new byte[size];
//    }
    public static volatile int f = -1;

    // set data f =2
    // get data f =1
    // free f = 0
    public void setData(byte[] foo, int start, int length) throws InterruptedException {
        data = new byte[length];
        System.arraycopy(foo, start, data, 0, length);        
        queue.add(data);
    }

    public static boolean checkData() {
        if (queue.isEmpty() == true) {
            return false;
        } else {
            return true;
        }
    }

    public static byte[] getData() throws InterruptedException {
        data = (byte[]) queue.remove();
        System.err.println("test get Data " + data.length + " = " + Tools.byte2str1(data));
        return data;
    }

    //--------------------------------
    public void createClientSide() {
        try {
            ClientSide = new JSch();
            session = ClientSide.getSession(UserSSH, RemoteHost);
            session.setPort(RemotePort);
            session.setPassword(PassSSH);
            session.setProxy((proxy.Proxy) this);
            session.connect();
            channelClient = session.openChannel("shell");
            channelClient.connect();
        } catch (JSchException ex) {
            Logs.Println(Logger.ERROR, ex.toString());
            Close();
        }
    }
//                  channel.setInputStream(System.in);
//            channel.setOutputStream(System.out);

    private void Relay() throws Exception {

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
//                ServerOutput.flush();
//                ServerOutput.close();
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
}
