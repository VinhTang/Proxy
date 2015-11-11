package ssh;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
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
    public Proxy Parent;
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
    int lwsize_max = 0x100000;
    //int lwsize_max=0x20000;  // 32*1024*4
    int lwsize = lwsize_max;  // local initial window size
    int lmpsize = 0x4000;     // local maximum packet size
////////////////////////////////////////////////////////////////////////////////

    public SessionSSH(Proxy proxy) {
        bucket = this;
        Parent = proxy;
        buf = new Buffer();
        packet = new Packet(buf);

        buf.putInt(this.lwsize);
        buf.putInt(this.lmpsize);
        Configure config = new Configure();

    }
//------------------------------------------------------------------------------

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
//------------------------------------------------------------------------------        
//                              send Server Vesion
//------------------------------------------------------------------------------
        byte[] foo = new byte[V_Proxy.length + 1];
        System.arraycopy(V_Proxy, 0, foo, 0, V_Proxy.length);
        foo[foo.length - 1] = (byte) '\n';
        Parent.SendToClient(foo);

//------------------------------------------------------------------------------        
//                              receive Client Vesion
//------------------------------------------------------------------------------        
        int len = 0;

        while (len < buf.buffer.length) {
            len++;
            buf.buffer[len] = GetByte();
            if (buf.buffer[len] == 10) {
                break;
            }
        }
        if (len < 7 || (buf.buffer[4] == '1' && buf.buffer[6] != '9'))// SSH-1.5 // SSH-1.99 or SSH-2.0 (7)
        {
            Logs.Println(proxy.Logger.INFO, "Proxy only support SSH 2.0!");
            Parent.Close();
        }

        V_Client = new byte[len];
        for (int i = 1; i < len; i++) {
            V_Client[i] = buf.buffer[i];
        }

        Logs.Println(proxy.Logger.INFO,
                "\n-------------------Start SSH Trans-------------------\n"
                + "-----------------------------------------------------\n"
        );
        Logs.Println(proxy.Logger.INFO, "Version Client: " + Tools.byte2str(V_Client));
        Logs.Println(proxy.Logger.INFO, "Version Proxy : " + Tools.byte2str(V_Proxy));

        if (cookie == null) {
            try {
                getConfig("random");
                Class c = Class.forName(getConfig("random"));
                cookie = (Cookie) (c.newInstance());
            } catch (Exception e) {
                Logs.Println(proxy.Logger.ERROR, e.toString());
            }
        }
//------------------------------------------------------------------------------        
//                              receive Key Exchange Intial (20)
//------------------------------------------------------------------------------

        buf = read(buf);
        if (buf.getCommand() != SSH_MSG_KEXINIT) {
            in_kex = false;
        }
        System.err.println(in_kex);
        Logs.Println(proxy.Logger.INFO, "SSH_MSG_KEXINIT received");

        KeyExchange kex = receive_kexinit(buf);
//------------------------------------------------------------------------------        
//                              send Key Exchange Intial (20)
//------------------------------------------------------------------------------

        //send kexinit 
        send_kexinit();

//------------------------------------------------------------------------------        
//                              receive DH Key exchange Intial (30)
//------------------------------------------------------------------------------
        while (true) {
            buf = read(buf);
            System.out.println(kex.getState());
            System.err.println(buf.getCommand());
            if (kex.getState() == buf.getCommand()) {
                kex_start_time = System.currentTimeMillis();
                boolean result = kex.next(buf);

                if (!result) {
                    //System.err.println("verify: "+result);
                    in_kex = false;
                    throw new ProxyException("verify: " + result);
                }
            } else {                
                in_kex = false;
                throw new ProxyException("invalid protocol(kex): " + buf.getCommand());
            }
            if (kex.getState() == KeyExchange.STATE_END) {
                break;
            }
        }


    }

////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////SSH ACTION CENTER//////////////////////////////
////////////////////////////////////////////////////////////////////////////////
    private boolean in_kex = false; // if Proxy have a key this Client in_kex = true

    private KeyExchange receive_kexinit(Buffer buf) throws Exception {
        int j = buf.getInt();
        if (j != buf.getLength()) {    // packet was compressed and
            buf.getByte();           // j is the size of deflated packet.
            I_S = new byte[buf.index - 5];
        } else {
            I_S = new byte[j - 1 - buf.getByte()];
        }
        System.arraycopy(buf.buffer, buf.s, I_S, 0, I_S.length);

        if (!in_kex) {     // We are in rekeying activated by the remote!
            send_kexinit();
        }

        guess = KeyExchange.guess(I_S, I_C);

        if (guess == null) {
            throw new ProxyException("Algorithm negotiation fail");
        }

        if (!isAuthed
                && (guess[KeyExchange.PROPOSAL_ENC_ALGS_CTOS].equals("none")
                || (guess[KeyExchange.PROPOSAL_ENC_ALGS_STOC].equals("none")))) {
            throw new ProxyException("NONE Cipher should not be chosen before authentification is successed.");
        }

        KeyExchange kex = null;
        try {
            Class c = Class.forName(getConfig(guess[KeyExchange.PROPOSAL_KEX_ALGS]));
            kex = (KeyExchange) (c.newInstance());
        } catch (Exception e) {
            throw new ProxyException(e.toString(), e);
        }

        kex.init(this, V_Proxy, V_Client, I_S, I_C);

        return kex;
    }

    //-----------------------------------------
    private void send_kexinit() throws Exception {
        if (in_kex) {
            return;
        }

        String cipherc2s = getConfig("cipher.c2s");
        String ciphers2c = getConfig("cipher.s2c");

        String[] not_available = checkCiphers(getConfig("CheckCiphers"));

        if (not_available != null && not_available.length > 0) {
            cipherc2s = Tools.diffString(cipherc2s, not_available);
            ciphers2c = Tools.diffString(ciphers2c, not_available);
            Logs.Println(proxy.Logger.DEBUG, "cipherc2s: send_kexinit() " + cipherc2s);
            if (cipherc2s == null || ciphers2c == null) {
                Logs.Println(proxy.Logger.ERROR, "There are not any available ciphers.");
            }
        }

        in_kex = true;
        kex_start_time = System.currentTimeMillis();

        buf = new Buffer();                // send_kexinit may be invoked
        packet = new Packet(buf);          // by user thread.
        packet.reset();
        Packet.setRandom(cookie);

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

        Logs.Println(proxy.Logger.INFO, "SSH_MSG_KEXINIT sent");
    }

//-----------------------------------------
    private void send_newkeys() throws Exception {
        // send SSH_MSG_NEWKEYS(21)
        packet.reset();
        buf.putByte((byte) SSH_MSG_NEWKEYS);
        write(packet);
        proxy.Logs.Println(proxy.Logger.INFO, "SSH_MSG_NEWKEYS sent");

    }

//-----------------------------------------
    private void receive_newkeys(Buffer buf, KeyExchange kex) throws Exception {
        updateKeys(kex);
        in_kex = false;
    }
//-----------------------------------------

    private void updateKeys(KeyExchange kex) throws Exception {
        byte[] K = kex.getK();
        byte[] H = kex.getH();
        HASH hash = kex.getHash();

//    String[] guess=kex.guess;
        if (session_id == null) {
            session_id = new byte[H.length];
            System.arraycopy(H, 0, session_id, 0, H.length);
        }

        /*
         Initial IV client to server:     HASH (K || H || "A" || session_id)
         Initial IV server to client:     HASH (K || H || "B" || session_id)
         Encryption key client to server: HASH (K || H || "C" || session_id)
         Encryption key server to client: HASH (K || H || "D" || session_id)
         Integrity key client to server:  HASH (K || H || "E" || session_id)
         Integrity key server to client:  HASH (K || H || "F" || session_id)
         */
        buf.reset();
        buf.putMPInt(K);
        buf.putByte(H);
        buf.putByte((byte) 0x41);
        buf.putByte(session_id);
        hash.update(buf.buffer, 0, buf.index);
        IVc2s = hash.digest();

        int j = buf.index - session_id.length - 1;

        buf.buffer[j]++;
        hash.update(buf.buffer, 0, buf.index);
        IVs2c = hash.digest();

        buf.buffer[j]++;
        hash.update(buf.buffer, 0, buf.index);
        Ec2s = hash.digest();

        buf.buffer[j]++;
        hash.update(buf.buffer, 0, buf.index);
        Es2c = hash.digest();

        buf.buffer[j]++;
        hash.update(buf.buffer, 0, buf.index);
        MACc2s = hash.digest();

        buf.buffer[j]++;
        hash.update(buf.buffer, 0, buf.index);
        MACs2c = hash.digest();

        try {
            Class c;
            String method;

            method = guess[KeyExchange.PROPOSAL_ENC_ALGS_STOC];
            c = Class.forName(getConfig(method));
            s2ccipher = (Cipher) (c.newInstance());
            while (s2ccipher.getBlockSize() > Es2c.length) {
                buf.reset();
                buf.putMPInt(K);
                buf.putByte(H);
                buf.putByte(Es2c);
                hash.update(buf.buffer, 0, buf.index);
                byte[] foo = hash.digest();
                byte[] bar = new byte[Es2c.length + foo.length];
                System.arraycopy(Es2c, 0, bar, 0, Es2c.length);
                System.arraycopy(foo, 0, bar, Es2c.length, foo.length);
                Es2c = bar;
            }
            s2ccipher.init(Cipher.DECRYPT_MODE, Es2c, IVs2c);
            s2ccipher_size = s2ccipher.getIVSize();

            method = guess[KeyExchange.PROPOSAL_MAC_ALGS_STOC];
            c = Class.forName(getConfig(method));
            s2cmac = (MAC) (c.newInstance());
            s2cmac.init(MACs2c);
            //mac_buf=new byte[s2cmac.getBlockSize()];
            s2cmac_result1 = new byte[s2cmac.getBlockSize()];
            s2cmac_result2 = new byte[s2cmac.getBlockSize()];

            method = guess[KeyExchange.PROPOSAL_ENC_ALGS_CTOS];
            c = Class.forName(getConfig(method));
            c2scipher = (Cipher) (c.newInstance());
            while (c2scipher.getBlockSize() > Ec2s.length) {
                buf.reset();
                buf.putMPInt(K);
                buf.putByte(H);
                buf.putByte(Ec2s);
                hash.update(buf.buffer, 0, buf.index);
                byte[] foo = hash.digest();
                byte[] bar = new byte[Ec2s.length + foo.length];
                System.arraycopy(Ec2s, 0, bar, 0, Ec2s.length);
                System.arraycopy(foo, 0, bar, Ec2s.length, foo.length);
                Ec2s = bar;
            }
            c2scipher.init(Cipher.ENCRYPT_MODE, Ec2s, IVc2s);
            c2scipher_size = c2scipher.getIVSize();

            method = guess[KeyExchange.PROPOSAL_MAC_ALGS_CTOS];
            c = Class.forName(getConfig(method));
            c2smac = (MAC) (c.newInstance());
            c2smac.init(MACc2s);

            method = guess[KeyExchange.PROPOSAL_COMP_ALGS_CTOS];
            initDeflater(method);

            method = guess[KeyExchange.PROPOSAL_COMP_ALGS_STOC];
            initInflater(method);
        } catch (Exception e) {
            if (e instanceof ProxyException) {
                throw e;
            }
            throw new ProxyException(e.toString(), e);
            //System.err.println("updatekeys: "+e); 
        }
    }
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
    private int s2ccipher_size = 8;
    private int c2scipher_size = 8;
    int[] uncompress_len = new int[1];

    private String[] checkCiphers(String ciphers) {
        if (ciphers == null || ciphers.length() == 0) {
            return null;
        }

        Logs.Println(proxy.Logger.DEBUG, "CheckCiphers: " + ciphers);

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
            Logs.Println(proxy.Logger.DEBUG, foo[i] + " is not available.");
        }

        return foo;
    }

//------------------------------------------------
    static boolean checkCipher(String cipher) {
        try {
            //System.err.println("cipher: checkCipher(String cipher)" + cipher);
            Class c = Class.forName(cipher);
            Cipher _c = (Cipher) (c.newInstance());

            _c.init(Cipher.ENCRYPT_MODE, new byte[_c.getBlockSize()], new byte[_c.getIVSize()]);
            Logs.Println(proxy.Logger.INFO, "OK   check Cipher: " + cipher);
            return true;
        } catch (Exception e) {
            Logs.Println(proxy.Logger.INFO, "fail checkCipher:  " + cipher);
            return false;

        }
    }
//------------------------------------------------------------------------------

    public void write(Packet packet) throws Exception {
        // System.err.println("in_kex="+in_kex+" "+(packet.buffer.getCommand()));
        long t = getTimeout();
        while (in_kex) {
            if (t > 0L && (System.currentTimeMillis() - kex_start_time) > t) {
                Logs.Println(proxy.Logger.DEBUG, "timeout in wating for rekeying process.");
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

//------------------------------------------------------------------------------
    public Buffer read(Buffer buf) throws Exception {
        int j = 0;
        while (true) {

            buf.reset();
            getByte(buf.buffer, buf.index, s2ccipher_size);
            buf.index += s2ccipher_size;

            if (s2ccipher != null) {
                s2ccipher.update(buf.buffer, 0, s2ccipher_size, buf.buffer, 0);
            }

            //packet cipher len
            j = ((buf.buffer[0] << 24) & 0xff000000)
                    | ((buf.buffer[1] << 16) & 0x00ff0000)
                    | ((buf.buffer[2] << 8) & 0x0000ff00)
                    | ((buf.buffer[3]) & 0x000000ff);
            // RFC 4253 6.1. Maximum Packet Length

            if (j < 5 || j > PACKET_MAX_SIZE) {
                start_discard(buf, s2ccipher, s2cmac, j, PACKET_MAX_SIZE);
            }

            int need = j + 4 - s2ccipher_size;
            //if(need<0){
            //  throw new IOException("invalid data");
            //}
            if ((buf.index + need) > buf.buffer.length) {
                byte[] foo = new byte[buf.index + need];
                System.arraycopy(buf.buffer, 0, foo, 0, buf.index);
                buf.buffer = foo;
            }

            if ((need % s2ccipher_size) != 0) {
                String message = "Bad packet length " + need;
                start_discard(buf, s2ccipher, s2cmac, j, PACKET_MAX_SIZE - s2ccipher_size);
            }

            if (need > 0) {
                getByte(buf.buffer, buf.index, need);
                buf.index += (need);
                if (s2ccipher != null) {
                    s2ccipher.update(buf.buffer, s2ccipher_size, need, buf.buffer, s2ccipher_size);
                }
            }

            if (s2cmac != null) {
                s2cmac.update(seqi);
                s2cmac.update(buf.buffer, 0, buf.index);

                s2cmac.doFinal(s2cmac_result1, 0);
                getByte(s2cmac_result2, 0, s2cmac_result2.length);
                if (!java.util.Arrays.equals(s2cmac_result1, s2cmac_result2)) {
                    if (need > PACKET_MAX_SIZE) {
                        throw new IOException("MAC Error");
                    }
                    start_discard(buf, s2ccipher, s2cmac, j, PACKET_MAX_SIZE - need);
                    continue;
                }
            }

            seqi++;

            if (inflater != null) {
                //inflater.uncompress(buf);
                int pad = buf.buffer[4];
                uncompress_len[0] = buf.index - 5 - pad;
                byte[] foo = inflater.uncompress(buf.buffer, 5, uncompress_len);
                if (foo != null) {
                    buf.buffer = foo;
                    buf.index = 5 + uncompress_len[0];
                } else {
                    System.err.println("fail in inflater");
                    break;
                }
            }

            int type = buf.getCommand() & 0xff;
            //System.err.println("read: "+type);
            if (type == SSH_MSG_DISCONNECT) {
                int reason_code = 0;
                byte[] description = null;
                byte[] language_tag = null;
                try {
                    buf.rewind();
                    buf.getInt();
                    buf.getShort();
                    reason_code = buf.getInt();
                    description = buf.getString();
                    language_tag = buf.getString();
                } catch (Exception e) {
                    Logs.Println(proxy.Logger.ERROR, "SSH_MSG_DISCONNECT: "
                            + reason_code
                            + " " + proxy.Tools.byte2str(description)
                            + " " + proxy.Tools.byte2str(language_tag));
                }
                //break;
            } else if (type == SSH_MSG_IGNORE) {
            } else if (type == SSH_MSG_UNIMPLEMENTED) {
                int reason_id = 0;
                try {
                    buf.rewind();
                    buf.getInt();
                    buf.getShort();
                    reason_id = buf.getInt();
                } catch (Exception e) {
                    Logs.Println(proxy.Logger.ERROR, "Received SSH_MSG_UNIMPLEMENTED for " + reason_id);
                }

            } else if (type == SSH_MSG_DEBUG) {
                buf.rewind();
                buf.getInt();
                buf.getShort();
                /*
                 byte always_display=(byte)buf.getByte();
                 byte[] message=buf.getString();
                 byte[] language_tag=buf.getString();
                 System.err.println("SSH_MSG_DEBUG:"+
                 " "+Util.byte2str(message)+
                 " "+Util.byte2str(language_tag));
                 */

//            } else if (type == SSH_MSG_CHANNEL_WINDOW_ADJUST) {
//                buf.rewind();
//                buf.getInt();
//                buf.getShort();
//                Channel c = Channel.getChannel(buf.getInt(), this);
//                if (c == null) {
//                } else {
//                    c.addRemoteWindowSize(buf.getInt());
//                }
//            } else if (type == UserAuth.SSH_MSG_USERAUTH_SUCCESS) {
//                isAuthed = true;
//                if (inflater == null && deflater == null) {
//                    String method;
//                    method = guess[KeyExchange.PROPOSAL_COMP_ALGS_CTOS];
//                    initDeflater(method);
//
//                    method = guess[KeyExchange.PROPOSAL_COMP_ALGS_STOC];
//                    initInflater(method);
//                }
                break;
            } else {
                break;
            }
        }
        buf.rewind(); //reset
        return buf;
    }

//------------------------------------------------------------------------------
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

        if (c2smac != null) {
            c2smac.update(seqo);
            c2smac.update(packet.buffer.buffer, 0, packet.buffer.index);
            c2smac.doFinal(packet.buffer.buffer, packet.buffer.index);
        }

        if (c2scipher != null) {
            byte[] buf = packet.buffer.buffer;
            c2scipher.update(buf, 0, packet.buffer.index, buf, 0);
        }

        if (c2smac != null) {
            packet.buffer.skip(c2smac.getBlockSize());
        }
    }

//------------------------------------------------------------------------------
    private void start_discard(Buffer buf, Cipher cipher, MAC mac,
            int packet_length, int discard) throws IOException {
        MAC discard_mac = null;

        if (!cipher.isCBC()) {
            Logs.Println(proxy.Logger.ERROR, "Packet corrupt");
        }

        if (packet_length != PACKET_MAX_SIZE && mac != null) {
            discard_mac = mac;
        }

        discard -= buf.index;

        while (discard > 0) {
            buf.reset();
            int len = discard > buf.buffer.length ? buf.buffer.length : discard;
            getByte(buf.buffer, 0, len);
            if (discard_mac != null) {
                discard_mac.update(buf.buffer, 0, len);
            }
            discard -= len;
        }

        if (discard_mac != null) {
            discard_mac.doFinal(buf.buffer, 0);
        }

    }

//------------------------------------------------------------------------------
    private void initInflater(String method) throws ProxyException {
        if (method.equals("none")) {
            inflater = null;
            return;
        }
        String foo = getConfig(method);
        if (foo != null) {
            if (method.equals("zlib")
                    || (isAuthed && method.equals("zlib@openssh.com"))) {
                try {
                    Class c = Class.forName(foo);
                    inflater = (Compression) (c.newInstance());
                    inflater.init(Compression.INFLATER, 0);
                } catch (Exception ee) {
                    throw new ProxyException(ee.toString(), ee);
                    //System.err.println(foo+" isn't accessible.");
                }
            }
        }
    }

    private void initDeflater(String method) throws ProxyException {
        if (method.equals("none")) {
            deflater = null;
            return;
        }
        String foo = getConfig(method);
        if (foo != null) {
            if (method.equals("zlib")
                    || (isAuthed && method.equals("zlib@openssh.com"))) {
                try {
                    Class c = Class.forName(foo);
                    deflater = (Compression) (c.newInstance());
                    int level = 6;
                    try {
                        level = Integer.parseInt(getConfig("compression_level"));
                    } catch (Exception ee) {
                    }
                    deflater.init(Compression.DEFLATER, level);
                } catch (Exception ee) {
                    throw new ProxyException(ee.toString(), ee);
                    //System.err.println(foo+" isn't accessible.");
                }
            }
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

    //----------------
    public void getByte(byte[] array, int begin, int length) throws IOException {
        do {
            int completed = 0;
            try {
                completed = Parent.ClientInput.read(array, begin, length);
            } catch (Exception e) {
            }
            if (completed < 0) {
                throw new IOException("End of IO Stream Read");
            }
            begin += completed;
            length -= completed;
        } while (length > 0);

        return;
    }

    //----------------
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
