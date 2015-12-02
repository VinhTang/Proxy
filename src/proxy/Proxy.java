/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package proxy;

import SSHServer.Buffer;
import SSHServer.Packet;
import SSHServer.IO;
import SSHServer.Packet;
import SSHServer.sshLinux;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.net.Socket;
import java.net.SocketException;
import SSHServer.sshServer;

import java.util.Queue;
import java.util.logging.Level;

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

    public Socket ClientSocket = null;
    public Socket ServerSocket = null;

    public InputStream inClient = null;
    public OutputStream outClient = null;
    public InputStream inLinux = null;
    public OutputStream outLinux = null;

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

            RemoteHost = communicator.getRemoteHost();
            RemotePort = communicator.getRemotePort();
            // sshserver check username/pass ? setRemotehost, of Proxy class : disconnect in sshserver

            Logs.Println(Logger.DEBUG, "ok. ProcessRelay() Proxy.java");

            ServerSide = new sshServer(this);
            LinuxSide = new sshLinux(this, UserSSH, Host);
            //start communication with sshServer
            boolean server = false;
            boolean linux = false;
            switch (communicator.Command) {
                case SOCK4.SC_CONNECT:
                    communicator.Reply_Connect();  // equal Connect()
                    //create SSH Trans
                    synchronized (bucket) {
                        ConnectToServer(RemoteHost, RemotePort);
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
                    System.err.println(server + "-" + linux);
                    break;
                }
            }
            Relay();
        } catch (Exception e) {
        }

    }

    ////////////////////////////////////////////////////////////////////////////
    private SSHServer.IO io;
    private SSHServer.IO iolinux;
    private SSHServer.sshServer ServerSide;
    private SSHServer.sshLinux LinuxSide;
    private SSHServer.Buffer buf = new Buffer();
    private SSHServer.Packet packet = new Packet(buf);

    public void Relay() throws Exception {

        io = ServerSide.getIOServer();
        iolinux = LinuxSide.getiolinux();
        System.err.println("vao relay");

        Thread CtoS = new Thread(new ClienttoServer(bucket, ServerSide, LinuxSide), "Clien to Server");
        Thread StoL = new Thread(new ServertoLinux(bucket, ServerSide, LinuxSide), "Server to Linux");
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
        //Disconnect Client <-> Proxy
        try {
            if (ClientSocket != null) {
                outClient.flush();
                outClient.close();
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
        LinuxSide.disconnect();
        ServerSide.disconnect();
        Logs.Println(Logger.INFO, "Proxy Closed !");
    }
    //-------------------------------------------

    //////////////////////////////////////////////////////////////////////////
    public void ConnectToServer(String Remotehost, int remoteport) throws IOException {
        //	Connect to the Remote Host

        if (RemoteHost.equals("")) {
            Close();
            Logs.Println(Logger.ERROR, "Invalid Remote Host Name - Empty String !!!");
            return;
        }

        ServerSocket = new Socket(RemoteHost, RemotePort);
//
//        
//        PrepareServer(); // prepare Stream for sshServer

    }

    //---------------------------------------
    /////////////////////////////////////////////////////////////
}

class ClienttoServer implements Runnable {

    sshLinux LinuxSide;
    sshServer ServerSide;
    Object bucket;

    Buffer buf;
    Packet packet;

    public ClienttoServer(Object Obj, sshServer server, sshLinux linux) {
        bucket = Obj;
        LinuxSide = linux;
        ServerSide = server;
        buf = new Buffer();
        packet = new Packet(buf);
    }

    @Override
    public void run() {
        int dlen = 0;

        while (true) {
            try {
                buf.reset();
                dlen = CheckClientData();
//            if (dlen < 0) {
                //Active = false;
//            }
                if (dlen > 0) {
                    SendToServer(buf, dlen);
                }
            } catch (Exception ex) {
                System.err.println("Linux to Server:" + ex.toString());
            }

        }
    }

    public int CheckClientData() throws Exception {

        //	The client side is not opened.
        if (ServerSide == null) {
            return -1;
        }
        int dlen = 0;
        try {
            buf.reset();
            buf = ServerSide.read(buf);
            dlen = buf.getLength();
        } catch (IOException e) {
//                Close();	//	Close the server on this exception
            return -1;
        }

//            if (dlen < 0) {
//                Close();
//            }
        return dlen;

    }

    private void SendToServer(Buffer buff, int dlen) throws Exception {
        if (LinuxSide == null) {
            return;
        }
        if (dlen <= 0 || dlen > buff.getLength()) {
            return;
        }
        buf.reset();
        buf = configbuffer(buff);

        try {
            LinuxSide.write(packet);
        } catch (IOException e) {
            Logs.Println(Logger.ERROR, "Sending data to server");
        }
    }

    private Buffer configbuffer(Buffer buff) {
        int lenght = buff.getInt();
        int pad = buff.getByte();
        buf.reset();
        packet.reset();
        System.arraycopy(buff.buffer, 5, buf.buffer, 5, lenght - pad - 1);
        buf.skip(lenght - pad - 1);

        //byte[] foo = new byte[lenght];
//        System.arraycopy(buff.buffer, 0, tes.buffer,0, buf.index);
//        System.err.println(test.getByte());
//        System.err.println(Tools.byte2str1(buf.getString()));
//        System.err.println(buf.getInt());
//        System.err.println(buf.getInt());
//        System.err.println(buf.getInt());
        return buf;
    }
}

    ////////////////////////////////////////////////////////////////////////////
class ServertoLinux implements Runnable {

    sshLinux LinuxSide;
    sshServer ServerSide;
    Object bucket;

    Buffer buf;
    Packet packet;

    public ServertoLinux(Object Obj, sshServer server, sshLinux linux) {
        bucket = Obj;
        LinuxSide = linux;
        ServerSide = server;
        buf = new Buffer();
        packet = new Packet(buf);
    }

    @Override
    public void run() {
        int dlen = 0;

        while (true) {
            try {
                buf.reset();
                dlen = CheckServerData();
//
//            if (dlen < 0) {
//                Active = false;
//            }
                if (dlen > 0) {
                    SendToClient(buf, dlen);
                }
            } catch (Exception ex) {
                System.err.println("Serverto Linux:" + ex.toString());
            }

        }
    }

    public int CheckServerData() throws Exception {

        //	The client side is not opened.
        if (LinuxSide == null) {
            return -1;
        }

        int dlen = 0;
        buf.reset();

        try {
            buf.reset();
            buf = LinuxSide.read(buf);
            dlen = buf.getLength();
        } catch (InterruptedIOException e) {
            return 0;
        } catch (IOException e) {
            Logs.Println(Logger.ERROR, "Server connection Closed! " + e.toString());
//                Close();	//	Close the server on this exception
            return -1;
        }

//            if (dlen < 0) {
//                Close();
//            }
        return dlen;

    }

    public void SendToClient(Buffer Buf, int Len) throws Exception {
        if (ServerSide == null) {
            return;
        }
        if (Len <= 0 || Len > Buf.getLength()) {
            return;
        }
        buf.reset();
        buf = configbuffer(Buf);

        try {
            ServerSide.write(packet);

        } catch (IOException e) {
            Logs.Println(proxy.Logger.ERROR, "Sending data to client");
        }
    }

    private Buffer configbuffer(Buffer buff) {
        int lenght = buff.getInt();
        int pad = buff.getByte();
        buf.reset();
        packet.reset();
        System.arraycopy(buff.buffer, 5, buf.buffer, 5, lenght - pad - 1);
        buf.skip(lenght - pad - 1);

        return buf;
    }
}
    ////////////////////////////////////////////////////////////////////////////
