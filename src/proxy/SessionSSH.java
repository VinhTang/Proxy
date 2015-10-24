/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package proxy;

import java.io.IOException;

/**
 *
 * @author Milky_Way
 */
public class SessionSSH {

    static private final String version = "SSH Proxy";
    ////////////////////////////////////////////////////////////////////////////
    public Proxy Parent = null;

    static final int SSH_MSG_DISCONNECT = 1;
    static final int SSH_MSG_IGNORE = 2;
    static final int SSH_MSG_UNIMPLEMENTED = 3;
    static final int SSH_MSG_DEBUG = 4;
    static final int SSH_MSG_SERVICE_REQUEST = 5;
    static final int SSH_MSG_SERVICE_ACCEPT = 6;
    static final int SSH_MSG_KEXINIT = 20;
    static final int SSH_MSG_NEWKEYS = 21;
    static final int SSH_MSG_KEXDH_INIT = 30;
    static final int SSH_MSG_KEXDH_REPLY = 31;
    static final int SSH_MSG_KEX_DH_GEX_GROUP = 31;
    static final int SSH_MSG_KEX_DH_GEX_INIT = 32;
    static final int SSH_MSG_KEX_DH_GEX_REPLY = 33;
    static final int SSH_MSG_KEX_DH_GEX_REQUEST = 34;
    static final int SSH_MSG_GLOBAL_REQUEST = 80;
    static final int SSH_MSG_REQUEST_SUCCESS = 81;
    static final int SSH_MSG_REQUEST_FAILURE = 82;
    static final int SSH_MSG_CHANNEL_OPEN = 90;
    static final int SSH_MSG_CHANNEL_OPEN_CONFIRMATION = 91;
    static final int SSH_MSG_CHANNEL_OPEN_FAILURE = 92;
    static final int SSH_MSG_CHANNEL_WINDOW_ADJUST = 93;
    static final int SSH_MSG_CHANNEL_DATA = 94;
    static final int SSH_MSG_CHANNEL_EXTENDED_DATA = 95;
    static final int SSH_MSG_CHANNEL_EOF = 96;
    static final int SSH_MSG_CHANNEL_CLOSE = 97;
    static final int SSH_MSG_CHANNEL_REQUEST = 98;
    static final int SSH_MSG_CHANNEL_SUCCESS = 99;
    static final int SSH_MSG_CHANNEL_FAILURE = 100;

    private static final int PACKET_MAX_SIZE = 256 * 1024;

    private byte[] V_Client;                                 // Client version
    private byte[] V_Proxy = Tools.str2byte("SSH-2.0-" + version); // Proxy version

    private byte[] I_C; // the payload of the client's SSH_MSG_KEXINIT
    private byte[] I_S; // the payload of the server's SSH_MSG_KEXINIT
    private byte[] K_S; // the host key

    private byte[] session_id;

    private byte[] IVc2s;
    private byte[] IVs2c;
    private byte[] Ec2s;
    private byte[] Es2c;
    private byte[] MACc2s;
    private byte[] MACs2c;

    private int seqi = 0;
    private int seqo = 0;

    String[] guess = null;

    //private byte[] mac_buf;
    private byte[] s2cmac_result1;
    private byte[] s2cmac_result2;

    private int timeout = 0;

    private boolean isConnected = false;

    private boolean isAuthed = false;

    private Thread connectThread = null;
    private Object lock = new Object();

    boolean x11_forwarding = false;
    boolean agent_forwarding = false;

    private java.util.Hashtable config = null;

    private String hostKeyAlias = null;
    private int serverAliveInterval = 0;
    private int serverAliveCountMax = 1;

    protected boolean daemon_thread = false;

    private long kex_start_time = 0L;

    ////////////////////////////////////////////////////////////////////////////
    public SessionSSH(Proxy proxy) {
        Parent = proxy;
    }

    public void Connect() {

        byte b;

        //send Vesion
        byte[] foo = new byte[V_Proxy.length + 1];
        System.arraycopy(V_Proxy, 0, foo, 0, V_Proxy.length);
        foo[foo.length - 1] = (byte) '\n';
        Parent.SendToClient(foo);

        int len = 0;
        //get respone
        Parent.Buffer = new byte[Parent.Bufflen];
        byte[] buf = new byte[1024];

        while (true) {
            len++;
            buf[len] = GetByte();
            if (buf[len] == 10) {
                break;
            }
        }
        if (len < 7 || (buf[4] == '1' && buf[6] != '9'))// SSH-1.5 // SSH-1.99 or SSH-2.0 (7)
        {
            Logs.Error("Proxy only support SSH 2.0!");
            Parent.Close();
        }

        V_Client = new byte[len];
        for (int i = 1; i < len; i++) {
            V_Client[i] = buf[i];
        }
        Logs.Error("-------------------Start SSH Trans-------------------\n"
                + "-----------------------------------------------------\n");
        Logs.Println("Version Client: " + Tools.byte2String(V_Client));
        Logs.Println("Version Proxy : " + Tools.byte2String(V_Proxy));
    }

    ////////////////////////////////////////////////////////////////////////////
//----------------
    protected byte GetByte() {
        byte b;
        try {
            b = Parent.GetByteFromClient();

        } catch (Exception e) {
            b = 0;
        }
        return b;
    }

}
