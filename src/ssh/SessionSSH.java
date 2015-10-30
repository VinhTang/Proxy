/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package ssh;

import java.io.IOException;

import proxy.Logs;
import proxy.Proxy;
import proxy.Tools;


/**
 *
 * @author Milky_Way
 */
public class SessionSSH {

    static private final String version = "SSH Proxy";
    ////////////////////////////////////////////////////////////////////////////
    public Proxy Parent = null;
    protected Object bucket;

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

    Buffer buf;
    Packet packet;
    static Cookie cookie;   // cookie
    String[] guess = null;

    private Cipher s2ccipher;
    private Cipher c2scipher;
    private MAC s2cmac;
    private MAC c2smac;
    private Compression deflater;
    private Compression inflater;
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

    //----------------------------------------------
    public int getTimeout() {
        return timeout;
    }

    ////////////////////////////////////////////////////////////////////////////
    public SessionSSH(Proxy proxy) {
        bucket = this;
        Parent = proxy;
        buf = new Buffer();
        packet = new Packet(buf);

    }

    public void Connect() throws Exception {

//      RFC 4253          SSH Transport Layer Protocol
//      ----------------------------------------------------
//      byte         SSH_MSG_KEXINIT   (21)
//      byte[16]     cookie (random bytes)
//      name-list    kex_algorithms
//      name-list    server_host_key_algorithms
//      name-list    encryption_algorithms_client_to_server
//      name-list    encryption_algorithms_server_to_client
//      name-list    mac_algorithms_client_to_server
//      name-list    mac_algorithms_server_to_client
//      name-list    compression_algorithms_client_to_server
//      name-list    compression_algorithms_server_to_client
//      name-list    languages_client_to_server
//      name-list    languages_server_to_client
//      boolean      first_kex_packet_follows
//      uint32       0 (reserved for future extension)
//      ----------------------------------------------------        
        //send Vesion
        byte[] foo = new byte[V_Proxy.length + 1];
        System.arraycopy(V_Proxy, 0, foo, 0, V_Proxy.length);
        foo[foo.length - 1] = (byte) '\n';
        Parent.SendToClient(foo);

        int len = 0;

        if (cookie == null) {
            try {
                getConfig("random");
                Class c = Class.forName("ssh.Random");
                cookie = (Cookie) (c.newInstance());
            } catch (Exception e) {
                Logs.Error(e);
            }
        }
        Packet.setRandom(cookie);
//        System.err.print("Cookie: "+ cookie);
//        cookie.fill(buf.buffer, buf.index, 16);
//        for(int i =0 ; i <=buf.buffer.length; i++)
//            System.out.println(i+": "+ buf.buffer[i]);

//get respone----------------------------------------------------
//        Parent.Buffer = new byte[Parent.Bufflen];
//        byte[] buf = new byte[1024];
        while (true) {
            len++;
            buf.buffer[len] = GetByte();
            if (buf.buffer[len] == 10) {
                break;
            }
        }
        if (len < 7 || (buf.buffer[4] == '1' && buf.buffer[6] != '9'))// SSH-1.5 // SSH-1.99 or SSH-2.0 (7)
        {
            Logs.Error("Proxy only support SSH 2.0!");
            Parent.Close();
        }

        V_Client = new byte[len];
        for (int i = 1; i < len; i++) {
            V_Client[i] = buf.buffer[i];
        }

        //free buf
        buf = null;

        Logs.Error("\n-------------------Start SSH Trans-------------------\n"
                + "-----------------------------------------------------\n");
        Logs.Println("Version Client: " + Tools.byte2String(V_Client));
        Logs.Println("Version Proxy : " + Tools.byte2String(V_Proxy));

        //send kexinit 
        send_kexinit();

    }

    /////////////////////////////SSH ACTION/////////////////////////////////////
    private boolean in_kex = false; // if Proxy have a key this Client in_kex = true

    private void send_kexinit() throws Exception {
        if (in_kex) {
            return;
        }

        String cipherc2s = getConfig("cipher.c2s");
        String ciphers2c = getConfig("cipher.s2c");
        System.err.println("getConfig(\"CheckCiphers\"): send_kexinit() "+ getConfig("CheckCiphers"));
        String[] not_available = checkCiphers(getConfig("CheckCiphers"));
        System.err.println("not_available: "+not_available);
        if (not_available != null && not_available.length > 0) {
            cipherc2s = Tools.diffString(cipherc2s, not_available);
            ciphers2c = Tools.diffString(ciphers2c, not_available);
            System.err.println("cipherc2s: send_kexinit() "+cipherc2s);
            System.err.println("ciphers2c: send_kexinit() "+ciphers2c);
            if (cipherc2s == null || ciphers2c == null) {
                Logs.Println("There are not any available ciphers.");
            }
        }

        in_kex = true;
        kex_start_time = System.currentTimeMillis();

        // byte      SSH_MSG_KEXINIT(20)
        // byte[16]  cookie (random bytes)
        // string    kex_algorithms
        // string    server_host_key_algorithms
        // string    encryption_algorithms_client_to_server
        // string    encryption_algorithms_server_to_client
        // string    mac_algorithms_client_to_server
        // string    mac_algorithms_server_to_client
        // string    compression_algorithms_client_to_server
        // string    compression_algorithms_server_to_client
        // string    languages_client_to_server
        // string    languages_server_to_client
        Buffer buf = new Buffer();                // send_kexinit may be invoked
        Packet packet = new Packet(buf);          // by user thread.
        packet.reset();

        buf.putByte((byte) SSH_MSG_KEXINIT);
        synchronized (cookie) {
            cookie.fill(buf.buffer, buf.index, 16);
            buf.skip(16);
        }
        buf.putString(Tools.str2byte(getConfig("kex")));
        buf.putString(Tools.str2byte(getConfig("server_host_key")));
        buf.putString(Tools.str2byte(cipherc2s));
        buf.putString(Tools.str2byte(ciphers2c));
        buf.putString(Tools.str2byte(getConfig("mac.c2s")));
        buf.putString(Tools.str2byte(getConfig("mac.s2c")));
        buf.putString(Tools.str2byte(getConfig("compression.c2s")));
        buf.putString(Tools.str2byte(getConfig("compression.s2c")));
        buf.putString(Tools.str2byte(getConfig("lang.c2s")));
        buf.putString(Tools.str2byte(getConfig("lang.s2c")));
        buf.putByte((byte) 0);
        buf.putInt(0);

        // change to buf.buffer[5] to set padding lenght
        buf.setOffSet(5);
        I_C = new byte[buf.getLength()];
        buf.getByte(I_C);

        write(packet);

        Logs.Println("SSH_MSG_KEXINIT sent");
    }

//--------------------------------------------------------------------------
    public String getConfig(String key) {
        Object foo = null;
        if (config != null) {
            foo = config.get(key);
            if (foo instanceof String) {
                return (String) foo;
            }
        }
        foo = Configure.getConfig(key);
        if (foo instanceof String) {
            return (String) foo;
        }
        return null;
    }

    //--------------------------------------------------------------------------
    private String[] checkCiphers(String ciphers) {
        if (ciphers == null || ciphers.length() == 0) {
            return null;
        }

        Logs.Println("CheckCiphers: " + ciphers);

        java.util.Vector result = new java.util.Vector();
        String[] _ciphers = proxy.Tools.split(ciphers, ",");

        for (int i = 0; i < _ciphers.length; i++) {
            if (!checkCipher(getConfig(_ciphers[i]))) {
                result.addElement(_ciphers[i]);
            }
        }

        if (result.size() == 0) {
            return null;
        }
        String[] foo = new String[result.size()];

        System.arraycopy(result.toArray(), 0, foo, 0, result.size());

        for (int i = 0; i < foo.length; i++) {
            Logs.Println(foo[i] + " is not available.");
        }

        return foo;
    }

//--------------------------------------------------------------------------
    static boolean checkCipher(String cipher) {
        try {
            System.err.println("cipher: checkCipher(String cipher)"+cipher);
            Class c = Class.forName(cipher);
            Cipher _c = (Cipher) (c.newInstance());
            _c.init(Cipher.ENCRYPT_MODE,
                    new byte[_c.getBlockSize()],
                    new byte[_c.getIVSize()]);
            return true;
        } catch (Exception e) {
            return false;

        }
    }
//--------------------------------------------------------------------------

    public void write(Packet packet) throws Exception {
        // System.err.println("in_kex="+in_kex+" "+(packet.buffer.getCommand()));
        long t = getTimeout();
        while (in_kex) {
            if (t > 0L && (System.currentTimeMillis() - kex_start_time) > t) {
                Logs.Error("timeout in wating for rekeying process.");
            }
            byte command = packet.buffer.getCommand();
            //System.err.println("command: "+command);
            if (command == SSH_MSG_KEXINIT
                    || command == SSH_MSG_NEWKEYS
                    || command == SSH_MSG_KEXDH_INIT
                    || command == SSH_MSG_KEXDH_REPLY
                    || command == SSH_MSG_KEX_DH_GEX_GROUP
                    || command == SSH_MSG_KEX_DH_GEX_INIT
                    || command == SSH_MSG_KEX_DH_GEX_REPLY
                    || command == SSH_MSG_KEX_DH_GEX_REQUEST
                    || command == SSH_MSG_DISCONNECT) {
                break;
            }
            try {
                Thread.sleep(10);
            } catch (java.lang.InterruptedException e) {
            };
        }
        _write(packet);
    }

    //-----------------------------------------------------
    private void _write(Packet packet) throws Exception {
        synchronized (bucket) {

            encode(packet);
            if (Parent.ClientOutput != null) {
                put(packet);
                seqo++;
            }
        }
    }

    //-----------------------------------------------------
    private int s2ccipher_size = 8;
    private int c2scipher_size = 8;

    public void encode(Packet packet) throws Exception {

        if (deflater != null) {
            packet.buffer.index = deflater.compress(packet.buffer.buffer, 5, packet.buffer.index);
        }

        if (c2scipher != null) {
            //packet.padding(c2scipher.getIVSize());
            packet.padding(c2scipher_size);
            int pad = packet.buffer.buffer[4];
            synchronized (cookie) {
                cookie.fill(packet.buffer.buffer, packet.buffer.index - pad, pad);
            }
        } else {
            packet.padding(8);
        }
        System.err.println("c2smac: "+c2smac);
        if (c2smac != null) {
            c2smac.update(seqo);
            c2smac.update(packet.buffer.buffer, 0, packet.buffer.index);
            c2smac.doFinal(packet.buffer.buffer, packet.buffer.index);
        }
        System.err.println("c2scipher: "+c2scipher);
        if (c2scipher != null) {
            byte[] buf = packet.buffer.buffer;
            c2scipher.update(buf, 0, packet.buffer.index, buf, 0);
        }
        
        System.err.println("c2smac: "+c2smac);
        if (c2smac != null) {
            packet.buffer.skip(c2smac.getBlockSize());
        }
    }
////////////////////////////////////////////////////////////////////////////////
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

    //------------------
    public void put(Packet p) throws IOException, java.net.SocketException {
        Parent.ClientOutput.write(p.buffer.buffer, 0, p.buffer.index);
        Parent.ClientOutput.flush();
    }

    //------------------

    void put(byte[] array, int begin, int length) throws IOException {
        Parent.ClientOutput.write(array, begin, length);
        Parent.ClientOutput.flush();
    }
    //------------------
//    void put_ext(byte[] array, int begin, int length) throws IOException {
//        Parent.ClientOutput.write(array, begin, length);
//        Parent.ClientOutput.flush();
//    }
////////////////////////////////////////////////////////////////////////////////
}
