package SSHServer;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import java.net.Socket;
import proxy.Logs;
import proxy.Proxy;
import proxy.Tools;

/**
 *
 * @author Milky_Way
 */
public class sshServer {

    static private final String version = "OpenSSH_5.3";
    ////////////////////////////////////////////////////////////////////////////
    protected Object parent;
    proxy.Proxy _proxy;
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

    public String KEX_ALGS;
    private Cipher s2ccipher;
    private Cipher c2scipher;

    private MAC s2cmac;
    private MAC c2smac;

    private Compression deflater;
    private Compression inflater;

    //private byte[] mac_buf;
    private byte[] c2smac_result1;
    private byte[] c2smac_result2;

    private int timeout = 0;

    private volatile boolean isConnected = false;

    private volatile boolean isAuthed = false;

    //private final Object parent  = null;
    private java.util.Hashtable config = null;

    private String hostKeyAlias = null;
    private int serverAliveInterval = 0;
    private int serverAliveCountMax = 1;

    protected boolean daemon_thread = false;

    private long kex_start_time = 0L;

    int max_auth_tries = 6;
    int auth_failures = 0;

    IO io = null;
    IO iolinux = null;

    Socket Sock;
    InputStream in = null;
    OutputStream out = null;
    InputStream inlinux = null;
    OutputStream outlinux = null;
//    String usernameProxy = null;
//    byte[] passwordProxy = null;
///////////////////////////////////////////////////////
    UserAuth ua;
    boolean auth = false;
    boolean auth_cancel = false;

// --- method authen choose
    String methodname = null;
// --- authen: password
    String username = null;
    byte[] password = null;
    // String Susername = null;
    byte[] Spassword = null;
// --- authen: publickey
    byte[] algs_auth = null;
    byte[] publicblob_auth = null;
    // ---
    boolean firstcheck = true;
///////////////////////////////////////////////////////
    static final int buffer_margin = 32 + // maximum padding length
            20 + // maximum mac length
            32;  // margin for deflater; deflater may inflate data

    //----------------------------------------------
    public int getTimeout() {
        return timeout;
    }
    int lwsize_max = 0x100000;
    //int lwsize_max=0x20000;  // 32*1024*4
    int lwsize = lwsize_max;  // local initial window size
    int lmpsize = 0x4000;     // local maximum packet size
////////////////////////////////////////////////////////////////////////////////

    public sshServer(Proxy proxy) {
        this.parent = this;
        _proxy = proxy;
        //parent = proxy;
        io = new IO();
    }

    public sshServer getSessionServer() {
        return this;
    }

    public IO getIOServer() {
        return this.io;
    }
//------------------------------------------------------------------------------

    private void setStream() {
        synchronized (parent) {
            try {
                //Client 
                in = _proxy.inClient;
                io.setInputStream(in);
                out = _proxy.outClient;
                io.setOutputStream(out);

            } catch (Exception e) {
                //System.err.println(e.toString());
            }
        }
    }

    public InputStream getInputstream() {
        return in;
    }

    public InputStream getLinuxInputstream() {
        return inlinux;
    }

    public OutputStream getOutputstream() {
        return out;
    }

    public OutputStream getLinuxOutputstream() {
        return outlinux;
    }

    public boolean isConnected() {
        return isConnected;
    }

    public boolean Connect() throws Exception {
        setStream();
        auth_failures = 0;
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
        if (isConnected) {
            throw new ProxyException("session is already connected");
        }
        Buffer buf = new Buffer();
        Packet packet = new Packet(buf);

        try {

//------------------------------------------------------------------------------        
//                              send sshServer Vesion
//------------------------------------------------------------------------------
            buf.reset();
            byte[] foo = new byte[V_Proxy.length + 1];
            System.arraycopy(V_Proxy, 0, foo, 0, V_Proxy.length);
            foo[foo.length - 1] = (byte) '\n';
            io.put(foo, 0, foo.length);

//------------------------------------------------------------------------------        
//                              receive Client Vesion
//------------------------------------------------------------------------------        
            int i = 0, j = 0;

            while (true) {
                i = 0;
                j = 0;
                while (i < buf.buffer.length) {

                    j = io.getByte();

                    if (j < 0) {
                        break;
                    }
                    buf.buffer[i] = (byte) j;
                    i++;
                    if (j == 10) {
                        break;
                    }
                }
                if (j < 0) {
                    throw new ProxyException("connection is closed by foreign host");
                }

                if (buf.buffer[i - 1] == 10) {    // 0x0a
                    i--;
                    if (i > 0 && buf.buffer[i - 1] == 13) {  // 0x0d
                        i--;
                    }
                }

                if (i <= 3
                        || ((i != buf.buffer.length)
                        && (buf.buffer[0] != 'S' || buf.buffer[1] != 'S'
                        || buf.buffer[2] != 'H' || buf.buffer[3] != '-'))) {
                    // It must not start with 'SSH-'
                    //System.err.println(new String(buf.buffer, 0, i);
                    continue;
                }

                if (i == buf.buffer.length
                        || i < 7 || // SSH-1.99 or SSH-2.0
                        (buf.buffer[4] == '1' && buf.buffer[6] != '9') // SSH-1.5
                        ) {
                    throw new ProxyException("invalid server's version string");
                }
                break;
            }

            V_Client = new byte[i];
            System.arraycopy(buf.buffer, 0, V_Client, 0, i);
            isConnected = true;

            Logs.Println(proxy.Logger.INFO, "Version Client: " + Tools.byte2str(V_Client), true);
            Logs.Println(proxy.Logger.INFO, "Version Proxy : " + Tools.byte2str(V_Proxy), true);

            if (cookie == null) {
                try {
                    getConfig("random");
                    Class c = Class.forName(getConfig("random"));
                    cookie = (Cookie) (c.newInstance());
                } catch (Exception e) {                    
                }
            }
//------------------------------------------------------------------------------        
//                              receive Key Exchange Intial (20)
//------------------------------------------------------------------------------

            buf = read(buf);

            if (buf.getCommand() != SSH_MSG_KEXINIT) {
                in_kex = false;
            }

            Logs.Println(proxy.Logger.DEBUG, "SSH_MSG_KEXINIT received",true);
            receive_kexinit(buf);

//------------------------------------------------------------------------------     
//                              send Key Exchange Intial (20)
//------------------------------------------------------------------------------        
            send_kexinit();
//------------------------------------------------------------------------------        
//                              DH Key exchange 
//------------------------------------------------------------------------------
            KeyExchange kex = null;

            try {
                KEX_ALGS = guess[KeyExchange.PROPOSAL_KEX_ALGS];
                Class c = Class.forName(getConfig(KEX_ALGS));
                kex = (KeyExchange) (c.newInstance());
            } catch (Exception e) {
                throw new ProxyException(e.toString(), e);
            }
            //----------------------

            kex.init(this, V_Proxy, V_Client, I_S, I_C);
//------------------------------------------------------------------------------        
//                              receive SSH_MSG_NEWKEYS (21)
//------------------------------------------------------------------------------           

            // receive SSH_MSG_NEWKEYS(21)
            buf.reset();
            buf = read(buf);
            if (buf.getCommand() == SSH_MSG_NEWKEYS) {
                Logs.Println(proxy.Logger.DEBUG, "SSH_MSG_NEWKEYS received",true);
                in_kex = false;
                send_newkeys();
                updateKeys(kex);

            } else {
                proxy.Logs.Println(proxy.Logger.INFO, "invalid signal. Connect Resfuse.",true);
                disconnectpacket("Invalid signal. Connect Resfuse");
                disconnect();
                _proxy.Close();
            }
//------------------------------------------------------------------------------        
//                              Authentication
//------------------------------------------------------------------------------     

            ua = null;
            auth = false;
            auth_cancel = false;
            try {
                Class c = Class.forName(getConfig("userauth.none"));
                ua = (UserAuth) (c.newInstance());
            } catch (Exception e) {
                throw new ProxyException(e.toString(), e);
            }
            auth = ua.start(this);
            auth_cancel = true;
//
//            try {
//                String s = getConfig("MaxAuthTries");
//                if (s != null) {
//                    max_auth_tries = Integer.parseInt(s);
//                }
//            } catch (NumberFormatException e) {
//                throw new ProxyException("MaxAuthTries: " + getConfig("MaxAuthTries"), e);
//            }
//            String smethods = null;
//            if (auth == true) {
//                smethods = ((UserAuthNone) ua).getMethods();
//            } else {
//                disconnectpacket("");
//                disconnect();
//            }
//
//            String[] smethoda = Tools.split(smethods, ",");
//
//            //-----------
//            buf.reset();
//            buf = read(buf);
//
//            if (buf.getCommand() == UserAuth.SSH_MSG_USERAUTH_REQUEST) {
//                buf.getInt();
//                buf.getByte();
//                buf.getByte();
//                username = Tools.byte2str(buf.getString());
//                byte[] servicename = buf.getString();
//                methodname = Tools.byte2str(buf.getString());
//            } else {
//                Logs.Println(proxy.Logger.INFO, "Unexpect statement! " + buf.getByte());
//                disconnectpacket("Unexpect statement! " + buf.getByte());
//                disconnect();
//            }
//            if (Logs.getLogger().isEnabled(proxy.Logger.INFO)) {
//                String str = "User choose authentication methods: " + methodname;
//                Logs.Println(proxy.Logger.INFO, str);
//            }
//
//            for (i = 0; i < smethoda.length; i++) {
//
//                if (smethoda[i].equals(methodname) == true) {
//                    if (methodname.equals("password")) {
//                        int bool = buf.getByte();
//                        password = buf.getString();
//                    } else if (methodname.equals("publickey") == true) {
//                        int bool = buf.getByte();
//                        algs_auth = buf.getString();
//                        publicblob_auth = buf.getString();
//                    }
//                }
//            }
//
//            //--------------------
//            ua = null;
//            try {
//                Class c = null;
//                if (getConfig("userauth." + methodname) != null) {
//                    c = Class.forName(getConfig("userauth." + methodname));
//                    ua = (UserAuth) (c.newInstance());
//                }
//            } catch (Exception e) {
//                if (Logs.getLogger().isEnabled(proxy.Logger.WARN)) {
//                    Logs.Println(proxy.Logger.WARN, "failed to load " + methodname + " method");
//                    disconnectpacket("");
//                    disconnect();
//                }
//            }
//
//            //------------------test H password proxy---------------------------
//            HASH sha = null;
//            try {
//                Class c = Class.forName(getConfig("sha-1"));
//                sha = (HASH) (c.newInstance());
//                sha.init();
//            } catch (Exception ee) {
//                proxy.Logs.Println(proxy.Logger.ERROR, ee.toString());
//            }
//
//            Spassword = Tools.str2byte("321");
//            sha.update(Spassword, 0, Spassword.length);
//            Spassword = sha.digest();
////            StringBuffer sb = new StringBuffer();
////            for (byte e : password) {
////                sb.append(Integer.toHexString((int) (e & 0xff)));
////            }
////            System.err.println(sb.toString());
//            //------------------------------------------------------------------
//
//            while (auth_cancel == false) {
//                if (ua != null) {
//                    try {
//                        auth = ua.start(this);
//                        if (auth == true && Logs.getLogger().isEnabled(proxy.Logger.INFO)) {
//                            Logs.Println(proxy.Logger.INFO, "Authentication succeeded (" + methodname + ").");
//                            isAuthed = true;
//                            auth_cancel = true;
//
//                        } else {
//                            auth_failures++;
//                            System.err.println("SSH: " + auth_failures);
//                            System.err.println("SSH: " + max_auth_tries);
//                            if (auth_failures == max_auth_tries) {
//                                Logs.Println(proxy.Logger.INFO, "Client fail authentication: fail !");
//                                proxy.Logs.Println(proxy.Logger.INFO, "Too many times authen for user " + username);
//                                disconnectpacket("Too many times authen for user " + username);
//                                disconnect();
//                                auth_cancel = true;
//                            }
//                        }
//
//                    } catch (Exception ee) {
//                        //System.err.println("ee: "+ee); // SSH_MSG_DISCONNECT: 2 Too many authentication failures
//                        if (Logs.getLogger().isEnabled(proxy.Logger.WARN)) {
//                            Logs.Println(proxy.Logger.WARN, "an exception during authentication\n" + ee.toString());
//                        }
//                        disconnectpacket("Too many times authen for user " + username);
//                        disconnect();
//                    }
//                    //------------
//                }
//
//            }
            firstcheck = true;
            Logs.Println(proxy.Logger.INFO, "Connect success to client",true);
            return true;

        } catch (Exception e) {
            in_kex = false;
            try {
                if (isConnected) {
                    disconnectpacket(e.toString());
                }
            } catch (Exception ee) {
            }
            try {
                disconnect();
                return false;
            } catch (Exception ee) {
            }
            //e.printStackTrace();
            if (e instanceof RuntimeException) {
                throw (RuntimeException) e;
            }
            if (e instanceof ProxyException) {
                throw (ProxyException) e;
            }
            throw new ProxyException("Session.connect: " + e);
        }
    }

////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////SSH ACTION CENTER//////////////////////////////
////////////////////////////////////////////////////////////////////////////////
    //-----------------------------------------    
    private boolean in_kex = false; // if Proxy have a kex this Client in_kex = true

    //-----------------------------------------    
    private void receive_kexinit(Buffer buf) throws Exception {

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

            if (cipherc2s == null || ciphers2c == null) {
                Logs.Println(proxy.Logger.ERROR, "There are not any available ciphers.",true);
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

        Logs.Println(proxy.Logger.DEBUG, "SSH_MSG_KEXINIT sent",true);
    }

    //-----------------------------------------
    private void send_newkeys() throws Exception {
        // send SSH_MSG_NEWKEYS(21)
        buf.reset();
        packet.reset();
        buf.putByte((byte) SSH_MSG_NEWKEYS);
        write(packet);

        proxy.Logs.Println(proxy.Logger.DEBUG, "SSH_MSG_NEWKEYS sent",true);
    }

    //-----------------------------------------
    public void disconnectpacket(String message) throws Exception {
        message = "Proxy Alert: " + message;
        packet.reset();
        buf.checkFreeSize(1 + 4 * 3 + message.length() + 2 + buffer_margin);
        buf.putByte((byte) SSH_MSG_DISCONNECT);
        buf.putInt(3);
        buf.putString(proxy.Tools.str2byte(message));
        buf.putString(proxy.Tools.str2byte("en"));
        write(packet);

    }

    //-----------------------------------------
    public void disconnect() {
        if (!isConnected) {
            return;
        }

        try {
            if (io != null) {
                if (io.in != null) {
                    io.in.close();
                }
                if (io.out != null) {
                    io.out.close();
                }
                if (io.out_ext != null) {
                    io.out_ext.close();
                }
            }
        } catch (Exception e) {
        }

        io = null;
        _proxy.Close();
    }

//-----------------------------------------
    private void updateKeys(KeyExchange kex) throws Exception {
        byte[] K = kex.getK();
        byte[] H = kex.getH();
        HASH hash = kex.getHash();

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

            //-------------s2c CIPHER
            method = guess[KeyExchange.PROPOSAL_ENC_ALGS_CTOS];
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

            //-------------s2c MAC
            method = guess[KeyExchange.PROPOSAL_MAC_ALGS_STOC];
            c = Class.forName(getConfig(method));
            s2cmac = (MAC) (c.newInstance());
            MACs2c = expandKey(buf, K, H, MACs2c, hash, s2cmac.getBlockSize());
            s2cmac.init(MACs2c);
            //mac_buf=new byte[s2cmac.getBlockSize()];
            c2smac_result1 = new byte[s2cmac.getBlockSize()];
            c2smac_result2 = new byte[s2cmac.getBlockSize()];

            //-------------c2s CIPHER
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

            //-------------c2s MAC
            method = guess[KeyExchange.PROPOSAL_MAC_ALGS_CTOS];
            c = Class.forName(getConfig(method));
            c2smac = (MAC) (c.newInstance());
            MACc2s = expandKey(buf, K, H, MACc2s, hash, c2smac.getBlockSize());
            c2smac.init(MACc2s);

            //------------- Compression
            method = guess[KeyExchange.PROPOSAL_COMP_ALGS_CTOS];
            initDeflater(method);

            method = guess[KeyExchange.PROPOSAL_COMP_ALGS_STOC];
            initInflater(method);
        } catch (Exception e) {
            if (e instanceof ProxyException) {
                throw e;
            }
            throw new ProxyException(e.toString(), e);
        }
    }
//-----------------------------------------

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
    private int s2ccipher_size = 8;
    private int c2scipher_size = 8;

    private String[] checkCiphers(String ciphers) {
        if (ciphers == null || ciphers.length() == 0) {
            return null;
        }

        // Logs.Println(proxy.Logger.DEBUG, "CheckCiphers: " + ciphers);
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

//        for (int i = 0; i < foo.length; i++) {
//            Logs.Println(proxy.Logger.DEBUG, foo[i] + " is not available.");
//        }
        return foo;
    }

//------------------------------------------------
    static boolean checkCipher(String cipher) {
        try {

            Class c = Class.forName(cipher);
            Cipher _c = (Cipher) (c.newInstance());

            _c.init(Cipher.ENCRYPT_MODE, new byte[_c.getBlockSize()], new byte[_c.getIVSize()]);
            //Logs.Println(proxy.Logger.DEBUG, "OK   check Cipher: " + cipher);
            return true;
        } catch (Exception e) {
            //Logs.Println(proxy.Logger.DEBUG, "fail checkCipher:  " + cipher);
            return false;

        }
    }

    public void write(Packet packet) throws Exception {

        long t = getTimeout();
        while (in_kex) {
            if (t > 0L && (System.currentTimeMillis() - kex_start_time) > t) {
                Logs.Println(proxy.Logger.DEBUG, "timeout in wating for rekeying process.",true);
            }
            byte command = packet.buffer.getCommand();
            //System.err.println("SERVER [ send ] StoL: " + command);
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
    public void _write(Packet packet) throws Exception {

        synchronized (parent) {
            encode(packet);
            if (io != null) {
                io.put(packet);
                seqo++;
            }
        }
    }

//------------------------------------------------------------------------------
    public Buffer read(Buffer buf) throws Exception {
        int j = 0;
        while (true) {
            buf.reset();
            io.getByte(buf.buffer, buf.index, c2scipher_size);
            buf.index += c2scipher_size;
            if (c2scipher != null) {
                c2scipher.update(buf.buffer, 0, c2scipher_size, buf.buffer, 0);
            }
            j = ((buf.buffer[0] << 24) & 0xff000000)
                    | ((buf.buffer[1] << 16) & 0x00ff0000)
                    | ((buf.buffer[2] << 8) & 0x0000ff00)
                    | ((buf.buffer[3]) & 0x000000ff);

            // RFC 4253 6.1. Maximum Packet Length
            if (j < 5 || j > PACKET_MAX_SIZE) {
                start_discard(buf, c2scipher, c2smac, j, PACKET_MAX_SIZE);
            }
            int need = j + 4 - c2scipher_size;

            //if(need<0){
            //  throw new IOException("invalid data");
            //}
            if ((buf.index + need) > buf.buffer.length) {
                byte[] foo = new byte[buf.index + need];
                System.arraycopy(buf.buffer, 0, foo, 0, buf.index);
                buf.buffer = foo;
            }

            if ((need % c2scipher_size) != 0) {
                String message = "Bad packet length " + need;
                if (Logs.getLogger().isEnabled(proxy.Logger.FATAL)) {
                    Logs.Println(proxy.Logger.DEBUG, message,true);
                }
                start_discard(buf, c2scipher, c2smac, j, PACKET_MAX_SIZE - c2scipher_size);
            }

            if (need > 0) {
                io.getByte(buf.buffer, buf.index, need);
                buf.index += (need);
                if (c2scipher != null) {
                    c2scipher.update(buf.buffer, c2scipher_size, need, buf.buffer, c2scipher_size);
                }
            }

            if (c2smac != null) {
                c2smac.update(seqi);
                c2smac.update(buf.buffer, 0, buf.index);

                c2smac.doFinal(c2smac_result1, 0);
                io.getByte(c2smac_result2, 0, c2smac_result2.length);
                if (!java.util.Arrays.equals(c2smac_result1, c2smac_result2)) {
                    if (need > PACKET_MAX_SIZE) {
                        throw new IOException("MAC Error");
                    }
                    start_discard(buf, c2scipher, c2smac, j, PACKET_MAX_SIZE - need);
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
            //System.err.println("SERVER [ nhan ] StoL: " + type); // NHo xoa cho nay
            if (type == SSH_MSG_DISCONNECT) {
                buf.rewind();
                buf.getInt();
                buf.getShort();
                int reason_code = buf.getInt();
                byte[] description = buf.getString();
                byte[] language_tag = buf.getString();
                throw new ProxyException("SSH_MSG_DISCONNECT: "
                        + reason_code
                        + " " + Tools.byte2str(description)
                        + " " + Tools.byte2str(language_tag));
                //break;
            } else if (type == SSH_MSG_IGNORE) {
            } else if (type == SSH_MSG_UNIMPLEMENTED) {
                buf.rewind();
                buf.getInt();
                buf.getShort();
                int reason_id = buf.getInt();
                if (Logs.getLogger().isEnabled(proxy.Logger.DEBUG)) {
                    Logs.Println(proxy.Logger.DEBUG,
                            "Received SSH_MSG_UNIMPLEMENTED for " + reason_id,true);
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

            } else if (type == UserAuth.SSH_MSG_USERAUTH_SUCCESS) {
                isAuthed = true;
                if (inflater == null && deflater == null) {
                    String method;
                    method = guess[KeyExchange.PROPOSAL_COMP_ALGS_CTOS];
                    initDeflater(method);
                    method = guess[KeyExchange.PROPOSAL_COMP_ALGS_STOC];
                    initInflater(method);
                }
                break;
            } else {
                break;
            }
        }
        buf.rewind();
        return buf;
    }

//------------------------------------------------------------------------------
    int[] uncompress_len = new int[1];
    int[] compress_len = new int[1];

    public void encode(Packet packet) throws Exception {

//        System.err.println("        " + packet.buffer.index);
//if(packet.buffer.getCommand()==96){
//Thread.dumpStack();
//}
        if (deflater != null) {
            compress_len[0] = packet.buffer.index;
            packet.buffer.buffer = deflater.compress(packet.buffer.buffer, 5, compress_len);
            packet.buffer.index = compress_len[0];
        }
        if (s2ccipher != null) {
            //packet.padding(c2scipher.getIVSize());
            packet.padding(s2ccipher_size);
            int pad = packet.buffer.buffer[4];
            synchronized (cookie) {
                cookie.fill(packet.buffer.buffer, packet.buffer.index - pad, pad);
            }
        } else {
            packet.padding(8);
        }

        if (s2cmac != null) {
            s2cmac.update(seqo);
            s2cmac.update(packet.buffer.buffer, 0, packet.buffer.index);
            s2cmac.doFinal(packet.buffer.buffer, packet.buffer.index);
        }
        if (s2ccipher != null) {
            byte[] buf = packet.buffer.buffer;
            s2ccipher.update(buf, 0, packet.buffer.index, buf, 0);
        }
        if (s2cmac != null) {
            packet.buffer.skip(s2cmac.getBlockSize());
        }
    }
//------------------------------------------------------------------------------

    private void start_discard(Buffer buf, Cipher cipher, MAC mac,
            int packet_length, int discard) throws ProxyException, IOException {
        {
            MAC discard_mac = null;

            if (!cipher.isCBC()) {
                throw new ProxyException("Packet corrupt");
            }
            if (packet_length != PACKET_MAX_SIZE && mac != null) {
                discard_mac = mac;
            }

            discard -= buf.index;

            while (discard > 0) {
                buf.reset();
                int len = discard > buf.buffer.length ? buf.buffer.length : discard;
                io.getByte(buf.buffer, 0, len);
                if (discard_mac != null) {
                    discard_mac.update(buf.buffer, 0, len);
                }
                discard -= len;
            }

            if (discard_mac != null) {
                discard_mac.doFinal(buf.buffer, 0);
            }

            throw new ProxyException("Packet corrupt");
        }
    }

//------------------------------------------------------------------------------
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
                } catch (NoClassDefFoundError ee) {
                    throw new ProxyException(ee.toString(), ee);
                } catch (Exception ee) {
                    throw new ProxyException(ee.toString(), ee);
                    //System.err.println(foo+" isn't accessible.");
                }
            }
        }
    }

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
//------------------------------------------------------------------------------

    private byte[] expandKey(Buffer buf, byte[] K, byte[] H, byte[] key,
            HASH hash, int required_length) throws Exception {
        byte[] result = key;
        int size = hash.getBlockSize();
        while (result.length < required_length) {
            buf.reset();
            buf.putMPInt(K);
            buf.putByte(H);
            buf.putByte(result);
            hash.update(buf.buffer, 0, buf.index);
            byte[] tmp = new byte[result.length + size];
            System.arraycopy(result, 0, tmp, 0, result.length);
            System.arraycopy(hash.digest(), 0, tmp, result.length, size);
            Tools.bzero(result);
            result = tmp;
        }
        return result;
    }

////////////////////////////////////////////////////////////////////////////////
    //----------------
    public String GetPreferredAuthentications() {
        // 0:public key
        // 1:password
        // 2: none
        String cmethods = getConfig("PreferredAuthentications");
        //String[] smethoda = proxy.Tools.split(cmethods, ",");
        //return smethoda[1]; // password
        return cmethods;
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
////////////////////////////////////////////////////////////////////////////////
}
