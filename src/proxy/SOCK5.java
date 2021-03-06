/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package proxy;

import java.io.IOException;
import java.net.InetAddress;

/**
 *
 * @author Milky_Way
 */
public class SOCK5 extends SOCK4 {

    ////////////////////////////////////////////////////////////////////////////
    final byte SOCKS5_Version = 0x05;

    static final int MaxAddrLen = 255;

//--- Reply Codes ---
//     o  X'00' succeeded
//     o  X'01' general SOCKS server failure
//     o  X'02' connection not allowed by ruleset
//     o  X'03' Network unreachable
//     o  X'04' Host unreachable
//     o  X'05' Connection refused
//     o  X'06' TTL expired
//     o  X'07' Command not supported
//     o  X'08' Address type not supported
//     o  X'09' to X'FF' unassigned
    protected byte getSuccessCode() {
        return 00;
    }

    protected byte getConnectnotAllowedRuleset() {
        return 02;
    }

    protected byte getFailCode() {
        return 04;
    }

    //---------------------------------
    public byte RSV;			// Reserved.Must be'00'
    public byte ATYP;			// Address Type
    //---------------------------------
    static final int ADDR_Size[] = {-1, //'00' No such AType 
        4, //'01' IP v4 - 4Bytes
        -1, //'02' No such AType
        -1, //'03' First Byte is Len
        16 //'04' IP v6 - 16bytes
};
    //---------------------------------
    static final byte SRE_NoAuth[] = {(byte) 0x05, (byte) 0x00};
    static final byte SRE_Auth[] = {(byte) 0x05, (byte) 0x02};
    static final byte SRE_AuthSuccess[] = {(byte) 0x01, (byte) 0x00};
    static final byte SRE_AuthFail[] = {(byte) 0x01, (byte) 0x01};
    //---------------------------------
    public String Username = "";
    public String Password = "";

    public String getPassword() {
        return Password;
    }

    public String getUsername() {
        return Username;
    }

    ////////////////////////////////////////////////////////////////////////////
    ////////////////////////////////////////////////////////////////////////////
    public SOCK5(Proxy proxy) {

        super(proxy);
        DST_Addr = new byte[MaxAddrLen];
    }

    ////////////////////////////////////////////////////////////////////////////
    public boolean AuthenticateVersion(byte SOCKS_Ver)
            throws Exception {

        super.AuthenticateVersion(SOCKS_Ver); // Sets SOCKS Version...

        if (SOCKS_Version == SOCKS5_Version) {
            if (Check_Authentication() == true) {
                Reply_Auth(true);
                Authenticate();
                return true;
            } else {
//                Refuse_Authentication("SOCKS 5 - Not Supported Authentication!");
                Reply_Auth(false);
                return false;
            }

        } else {
            Refuse_Authentication("Incorrect SOCKS version : " + SOCKS_Version);
            throw new Exception("Not Supported SOCKS Version -'"
                    + SOCKS_Version + "'");
            
        }

    }

// Authenticate()
//-----------------------
// true   : Authen
// false  : No Auth
    private boolean Check_Authentication() {
        //get Method
        byte Methods_Num = GetByte();
        String Methods = "";

        for (int i = 0; i < Methods_Num; i++) {
            Methods += ",-" + GetByte() + '-';
        }
        if (Parent.Have_Authentication == true) {
            if (Methods.contains("-2-")) {
                return true;
            }
        }
        return false;
    }

    //-----------------------
    public void Refuse_Authentication(String msg) {

        Logs.PrintlnProxy(Logger.ERROR, "SOCKS 5 - Refuse Authentication: '" + msg + "'",true);
        Parent.SendToClient(SRE_Refuse);
        Parent.Close();
    }

    //-----------------------
    private void Reply_Auth(boolean flag) throws IOException {
        if (flag == true) {
            Parent.SendToClient(SRE_Auth);
//            Logs.PrintlnProxy(Logger.INFO, "SOCK5 authentication method establish!");
        }
        if (flag == false) {
            Parent.SendToClient(SRE_NoAuth);
//            Logs.PrintlnProxy(Logger.ERROR, "SOCK5 not support authentication method!");
        }

    }

    //-----------------------
    private void Authenticate() {
        GetUserInfo();
        Logs.setUsername(Username);
        Parent.SendToClient(SRE_AuthSuccess);
    }
    ////////////////////////////////////////////////////////////////////////////

    public void GetClientCommand() throws Exception {
//        +----+-----+-------+------+----------+----------+
//        |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
//        +----+-----+-------+------+----------+----------+
//        | 1  |  1  | X'00' |  1   | Variable |    2     |
//        +----+-----+-------+------+----------+----------+
        int Addr_Len;

        SOCKS_Version = GetByte();
        Command = GetByte();
        RSV = GetByte();
        ATYP = GetByte();

        //Address
        Addr_Len = ADDR_Size[ATYP];
        DST_Addr[0] = GetByte();   //Shift Out " " 0x0e
        if (ATYP == 0x03) {
            Addr_Len = DST_Addr[0] + 1;    // | len | [0]SO | 192 .... |
        }

        for (int i = 1; i < Addr_Len; i++) {
            DST_Addr[i] = GetByte();
        }

        //Port
        DST_Port[0] = GetByte();
        DST_Port[1] = GetByte();

        //---------------------
        if (SOCKS_Version != SOCKS5_Version) {
            Logs.Println(Logger.ERROR, "SOCKS 5 - Incorrect SOCKS Version of Command: "
                    + SOCKS_Version,true);
            Refuse_Command((byte) 0xFF);
            throw new Exception("Incorrect SOCKS Version of Command: "
                    + SOCKS_Version);
        }

        if ((Command < SC_CONNECT) || (Command > SC_UDP)) {
            Logs.Println(Logger.ERROR, "SOCKS 5 - GetClientCommand() - Unsupported Command : \"" + commName(Command) + "\"",true);
            Refuse_Command((byte) 0x07);
            throw new Exception("SOCKS 5 - Unsupported Command: \"" + Command + "\"");
        }

        if (ATYP == 0x04) {
            Logs.Println(Logger.ERROR, "SOCKS 5 - GetClientCommand() - Unsupported Address Type - IP v6",true);
            Refuse_Command((byte) 0x08);
            throw new Exception("Unsupported Address Type - IP v6");
        }

        if ((ATYP >= 0x04) || (ATYP <= 0)) {
            Logs.Println(Logger.ERROR, "SOCKS 5 - GetClientCommand() - Unsupported Address Type: " + ATYP,true);
            Refuse_Command((byte) 0x08);
            throw new Exception("SOCKS 5 - Unsupported Address Type: " + ATYP);
        }

        if (!Calculate_Address()) {  // Gets the IP Address 
            Refuse_Command((byte) 0x04);// Host Not Exists...
            throw new Exception("SOCKS 5 - Unknown Host/IP address '" + RemoteHost.toString() + "'");
        }

        Logs.Println(Logger.INFO, "SOCKS 5 - Accepted SOCKS5 Command: \"" + commName(Command) + "\"",true);
    }

    //--------------------
    private void GetUserInfo() {
        byte b;
        int version = GetByte();

        //USername
        int Userlen = Tools.byte2int(GetByte());

        byte[] User = null;
        for (int i = 0; i < Userlen; i++) {
            Username += (char) GetByte();
        }
 //       User = Username.getBytes();
//        Username = Tools.byte2str(User);

        //Password
        int Passlen = Tools.byte2int(GetByte());

        byte[] Pass = null;
        for (int i = 0; i < Passlen; i++) {
            Password += (char) GetByte();
        }
//       Pass = Password.getBytes();
//        Password = Tools.byte2str(User);

    }

    ////////////////////////////////////////////////////////////////////////////
    public void Reply_Command(byte ReplyCode) {
        //Logs.Println("SOCKS 5 - Reply to Client \"" + ReplyName(ReplyCode) + "\"");

        int port = 0;
        String DomainName = "0.0.0.0";
        InetAddress InetAdd = null;

        byte[] REPLY = new byte[10];
        byte IP[] = new byte[4];

        if (Parent.LinuxSocket != null) {
            InetAdd = Parent.LinuxSocket.getInetAddress();
            DomainName = InetAdd.toString();
            port = Parent.LinuxSocket.getLocalPort();
        } else {
            IP[0] = 0;
            IP[1] = 0;
            IP[2] = 0;
            IP[3] = 0;
            port = 0;
        }

        REPLY[0] = SOCKS5_Version;
        REPLY[1] = ReplyCode;	// Reply Code;
        REPLY[2] = 0x00;		// Reserved	'00'
        REPLY[3] = 0x01;		// DOMAIN NAME Type IP ver.4
        REPLY[4] = IP[0];
        REPLY[5] = IP[1];
        REPLY[6] = IP[2];
        REPLY[7] = IP[3];
        REPLY[8] = (byte) ((port & 0xFF00) >> 8);// Port High
        REPLY[9] = (byte) (port & 0x00FF);	  // Port Low

        Parent.SendToClient(REPLY);
    } // Reply_Command()
    ////////////////////////////////////////////////////////////////////////////

    private boolean CheckAccess() {
        //temp access

        return true;
    }
    ////////////////////////////////////////////////////////////////////////////

    public boolean Calculate_Address() {
        Calculate_AddressSOCK(ATYP);
        return true;
    }

    public void Calculate_AddressSOCK(byte AType) {

        switch (AType) {
            // Version IP 4
            case 0x01:
                RemoteHost = Tools.calcInetAddress(DST_Addr);
                RemotePort = Tools.calcPort(DST_Port);
                break;
            // Version IP DOMAIN NAME
            case 0x03:

                if (DST_Addr[0] <= 0) {
                    Logs.Println(Logger.ERROR, "SOCKS 5 - calcInetAddress() : BAD IP in command - size : " + DST_Addr[0],true);
                    return;
                }
                String sIA = "";

                for (int i = 1; i <= DST_Addr[0]; i++) {
                    sIA += (char) DST_Addr[i];

                }

                RemoteHost = sIA;
                RemotePort = Tools.calcPort(DST_Port);
                break;

        }

    }

    /////////////////////////////////////////////////////////////////	
}
