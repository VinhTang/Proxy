/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package proxy;


import java.net.InetAddress;

/**
 *
 * @author Milky_Way
 */
public class SOCK4 {

    public byte SOCKS_Version = 0;

    final byte SOCKS4_Version = 0x04;

    static byte SRE_Refuse[] = {(byte) 0x05, (byte) 0xFF};
    static byte SRE_Accept[] = {(byte) 0x05, (byte) 0x00};

    public Proxy Parent = null;

    public byte Command;
    public byte DST_Port[] = null;
    public byte DST_Addr[] = null;
    public byte UserID[] = null;

    static final byte SC_CONNECT = 0x01;
    static final byte SC_BIND = 0x02;
    static final byte SC_UDP = 0x03;	// Not allowed on SOCKS4

    //----------------------------------------------
    //--- Reply Codes ---
    protected byte getSuccessCode() {
        return 90;
    }

    protected byte getFailCode() {
        return 91;
    }
    //-------------------

    protected String RemoteHost = null;
    protected int RemotePort = 0;

    protected String Host = null;
    protected int HostPort = 0;

    //----------------------------------------------
    public String getHost() {
        return Host;
    }

    public int getHostPort() {
        return HostPort;
    }

    //-------
    public String getRemoteHost() {
        return RemoteHost;
    }

    public int getRemotePort() {
        return RemotePort;
    }
    //----------------------------------------------
    public String UID = "";

    ////////////////////////////////////////////////////////////////////////////
    ////////////////////////////////////////////////////////////////////////////
    public SOCK4(Proxy proxy) {
        Parent = proxy;

        DST_Addr = new byte[4];
        DST_Port = new byte[2];
    }

    ////////////////////////////////////////////////////////////////////////////
    public void GetClientCommand() throws Exception {

        byte b;

        //SOCK version was authen by AuthenticateVersion();
// 	+----+----+----+----+----+----+----+----+----+----+....+----+
//	| VN | CD | DSTPORT |      DSTIP        | USERID       |NULL|
//	+----+----+----+----+----+----+----+----+----+----+....+----+
//	   1    1      2              4           variable       1
        Command = GetByte();

        DST_Port[0] = GetByte();
        DST_Port[1] = GetByte();

        for (int i = 0; i < 4; i++) {
            DST_Addr[i] = GetByte();
        }

        while ((b = GetByte()) != 0x00) {
            UID += (char) b;
        }
        Calculate_Username();

        //------------------------
        if ((Command < SC_CONNECT)) {
            Refuse_Command((byte) 91);

        }

        if (!Calculate_Address()) { // get the IP Address
            Refuse_Command((byte) 92);

        }

        Logs.Println(Logger.INFO,"Accepted SOCKS 4 Command: \"" + commName(Command) + "\"");

    }

    //----------------------------------
    protected byte GetByte() {
        byte b;
        try {
            b = Parent.GetByteFromClient();

            //System.out.println(Byte.toString(b));
        } catch (Exception e) {
            b = 0;
        }
        return b;
    }
    ////////////////////////////////////////////////////////////////////////////

    //1. connect to Linux Server
    //2. if alive 
    //3. reply to client connect, create sshtunnel
    //4. create ssh connect to proxy
    //5. transfer data from client to server
    public void Reply_Connect() throws Exception {
        Logs.Println(Logger.DEBUG,"Connecting... ");
        //	Connect to the Remote Host

//        try {
//            Parent.ConnectToServer(ServerIP.getHostAddress(), ServerPort);
//
//        } catch (IOException e) {
//            Refuse_Command(getFailCode()); // Connection Refuseds
//            throw new Exception("Socks 4 - Can't connect to "
//                    + Logs.getSocketInfo(Parent.ServerSocket));
//        }
//
        Logs.Println(Logger.INFO,"Connected to " + Logs.getSocketInfo(Parent.ServerSocket));
        Reply_Command(getSuccessCode());

    }

    ////////////////////////////////////////////////////////////////////////////
    public void Calculate_Username() {
        String s = UID + " ";
        UserID = s.getBytes();
        
        Logs.Println(Logger.DEBUG,"USERID : " + Tools.byte2str(UserID));
        // Send USerID to check role
        //UserID[UserID.length - 1] = 0x00;
    }

    //-------------------------
    public boolean Calculate_Address() {
        //remote IP
        RemoteHost = Tools.calcInetAddress(DST_Addr);
        RemotePort = Tools.calcPort(DST_Port);

        Logs.Println(Logger.INFO,"RemoteHost/RemotePort: "+RemoteHost + "/" + RemotePort);

        Host = Parent.ClientSocket.getInetAddress().toString();
        HostPort = Parent.ClientSocket.getPort();
        
        Logs.Println(Logger.INFO,"Host/HostPort: "+Host + "/" + HostPort);
        if ((RemoteHost != null) && (RemotePort >= 0)) {
            return true;
        } else {
            return false;
        }
    }

    ////////////////////////////////////////////////////////////////////////////
    public void AuthenticateVersion(byte SOCK_Ver) throws Exception {
        SOCKS_Version = SOCK_Ver;
    }

    ////////////////////////////////////////////////////////////////////////////
    protected void Refuse_Command(byte ErrorCode) {
        Logs.Println(Logger.INFO,"Socks 4 - Refuse Command: \"" + ReplyName(ErrorCode) + "\"");
        Reply_Command(ErrorCode);
    }	// Refuse_Command()

    //-------------------------------------
    public void Reply_Command(byte ReplyCode) {
        Logs.Println(Logger.INFO,"Socks 4 reply: \"" + ReplyName(ReplyCode) + "\"");

        byte[] REPLY = new byte[8];
        REPLY[0] = 0;
        REPLY[1] = ReplyCode;
        REPLY[2] = DST_Port[0];
        REPLY[3] = DST_Port[1];
        REPLY[4] = DST_Addr[0];
        REPLY[5] = DST_Addr[1];
        REPLY[6] = DST_Addr[2];
        REPLY[7] = DST_Addr[3];

        Parent.SendToClient(REPLY);
    } // Reply_Command()
    ////////////////////////////////////////////////////////////////////////////

    public String commName(byte code) {

        switch (code) {
            case 0x01:
                return "CONNECT";
            case 0x02:
                return "BIND";
            case 0x03:
                return "UDP Association";

            default:
                return "Unknown Command";
        }
    }
    //----------------------------

    public String ReplyName(byte code) {

        switch (code) {
            case 0:
                return "SUCCESS";
            case 1:
                return "General SOCKS Server failure";
            case 2:
                return "Connection not allowed by ruleset";
            case 3:
                return "Network Unreachable";
            case 4:
                return "HOST Unreachable";
            case 5:
                return "Connection Refused";
            case 6:
                return "TTL Expired";
            case 7:
                return "Command not supported";
            case 8:
                return "Address Type not Supported";
            case 9:
                return "to 0xFF UnAssigned";

            case 90:
                return "Request GRANTED";
            case 91:
                return "Request REJECTED or FAILED";
            case 92:
                return "Request REJECTED - SOCKS server can't connect to Identd on the client";
            case 93:
                return "Request REJECTED - Client and Identd report diff user-ID";

            default:
                return "Unknown Command";
        }
    }
    ////////////////////////////////////////////////////////////////////////////

}
