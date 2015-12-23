package SSHServer;

import java.io.*;
import java.net.*;
import java.util.Vector;

import proxy.Tools;
import proxy.Logs;

public class sshLinux implements Runnable {

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

    private byte[] V_S;                                 // server version
    private byte[] V_C = Tools.str2byte("SSH-2.0-OpenSSH_5.3"); // client version

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
    private Cipher s2ccipher;
    private Cipher c2scipher;
    private MAC s2cmac;
    private MAC c2smac;
    //private byte[] mac_buf;
    private byte[] s2cmac_result1;
    private byte[] s2cmac_result2;

    private Compression deflater;
    private Compression inflater;

    private Socket socket;
    private int timeout = 0;

    private volatile boolean isConnected = false;

    private boolean isAuthed = false;
    boolean x11_forwarding = false;
    boolean agent_forwarding = false;

    static Cookie random;

    Buffer buf;
    Packet packet;

    static final int buffer_margin = 32 + // maximum padding length
            20 + // maximum mac length
            32;  // margin for deflater; deflater may inflate data

    private java.util.Hashtable config = null;
    private long kex_start_time = 0L;

    int max_auth_tries = 6;
    int auth_failures = 0;

    String org_host = "127.0.0.1";

    int port = 22;
    String remotehost;
    String usernameSSH;
    byte[] passwordSSH;

    private IO io;
    private IO iolinux;
    protected Object parent;
    InputStream in;
    OutputStream out;
    InputStream inlinux;
    OutputStream outlinux;
    proxy.Proxy _proxy;

    SocketFactory socket_factory = null;

    ////////////////////////////////////////////////////////////////////////////    
    ////////////////////////////////////////////////////////////////////////////
    public sshLinux(proxy.Proxy proxy, String _remotehost) throws ProxyException {

        this.parent = this;
        _proxy = proxy;
        remotehost = _remotehost;

        io = new IO();
        iolinux = new IO();
    }

    //-----------------------------------------
    public boolean connect() throws ProxyException {
        setStream();
        buf = new Buffer();
        packet = new Packet(buf);
        if (isConnected) {
            throw new ProxyException("session is already connected");
        }

        if (random == null) {
            try {
                Class c = Class.forName(getConfig("random"));
                random = (Cookie) (c.newInstance());
            } catch (Exception e) {
                throw new ProxyException(e.toString(), e);
            }
        }
        Packet.setRandom(random);

        Logs.Println(proxy.Logger.INFO, "Connecting to " + remotehost + " port " + port, true);

        isConnected = true;

        try {
            int i, j;
            {
                // Some Cisco devices will miss to read '\n' if it is sent separately.
                byte[] foo = new byte[V_C.length + 1];
                System.arraycopy(V_C, 0, foo, 0, V_C.length);
                foo[foo.length - 1] = (byte) '\n';
                iolinux.put(foo, 0, foo.length);
            }

            while (true) {
                i = 0;
                j = 0;

                while (i < buf.buffer.length) {
                    try {
                        j = iolinux.getByte();
                    } catch (Exception e) {
                        System.err.println(e.toString());
                    }

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
                    throw new ProxyException("connection is closed by foreign remotehost");
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

            V_S = new byte[i];
            System.arraycopy(buf.buffer, 0, V_S, 0, i);
//            System.err.println("nhan duoc V_S: (" + i + ") [" + new String(V_S) + "]");

            Logs.Println(proxy.Logger.INFO,
                    "Remote version string: " + Tools.byte2str(V_S), true);
            Logs.Println(proxy.Logger.INFO,
                    "Local version string: " + Tools.byte2str(V_C), true);

            send_kexinit();

            buf = read(buf);
            if (buf.getCommand() != SSH_MSG_KEXINIT) {
                in_kex = false;
                throw new ProxyException("invalid protocol: " + buf.getCommand());
            }

            Logs.Println(proxy.Logger.DEBUG,
                    "SSH_MSG_KEXINIT received", true);

            KeyExchangelinux kex = receive_kexinit(buf);

            while (true) {
                buf = read(buf);
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
                if (kex.getState() == KeyExchangelinux.STATE_END) {
                    break;
                }
            }

            send_newkeys();

            // receive SSH_MSG_NEWKEYS(21)
            buf = read(buf);
            //System.err.println("read: 21 ? "+buf.getCommand());
            if (buf.getCommand() == SSH_MSG_NEWKEYS) {

                Logs.Println(proxy.Logger.DEBUG,
                        "SSH_MSG_NEWKEYS received", true);

                receive_newkeys(buf, kex);

            } else {
                in_kex = false;
                throw new ProxyException("invalid protocol(newkyes): " + buf.getCommand());
            }

            try {
                String s = getConfig("MaxAuthTries");
                if (s != null) {
                    max_auth_tries = Integer.parseInt(s);
                }
            } catch (NumberFormatException e) {
                throw new ProxyException("MaxAuthTries: " + getConfig("MaxAuthTries"), e);
            }
            boolean auth = false;
            boolean auth_cancel = false;

            UserAuthlinux ua = null;

            try {
                Class c = Class.forName(getConfig("userauthlinux.none"));
                ua = (UserAuthlinux) (c.newInstance());
            } catch (Exception e) {
                throw new ProxyException(e.toString(), e);
            }

            auth = ua.start(this);

            String cmethods = getConfig("PreferredAuthentications");

            String[] cmethoda = Tools.split(cmethods, ",");

            String smethods = null;
            if (!auth) {
                smethods = ((UserAuthNonelinux) ua).getMethods();
                if (smethods != null) {
                    smethods = smethods.toLowerCase();
                } else {
                    // methods: publickey,password,keyboard-interactive
                    //smethods="publickey,password,keyboard-interactive";
                    smethods = cmethods;
                }
            }

            String[] smethoda = Tools.split(smethods, ",");

            int methodi = 0;

            loop:
            while (true) {

                while (!auth
                        && cmethoda != null && methodi < cmethoda.length) {

                    String method = cmethoda[methodi++];
                    boolean acceptable = false;
                    for (int k = 0; k < smethoda.length; k++) {
                        if (smethoda[k].equals(method)) {
                            acceptable = true;
                            break;
                        }
                    }
                    if (!acceptable) {
                        continue;
                    }

                    //System.err.println("  method: "+method);
                    String str = "Authentications that can continue: ";
                    for (int k = methodi - 1; k < cmethoda.length; k++) {
                        str += cmethoda[k];
                        if (k + 1 < cmethoda.length) {
                            str += ",";
                        }
                    }

                    ua = null;

                    try {
                        Class c = null;
                        if (getConfig("userauthlinux." + method) != null) {
                            c = Class.forName(getConfig("userauthlinux." + method));
                            ua = (UserAuthlinux) (c.newInstance());
                        }
                    } catch (Exception e) {
                    }

                    if (ua != null) {
                        auth_cancel = false;
                        try {
                            auth = ua.start(this);
                            Logs.Println(proxy.Logger.DEBUG,
                                    "Authentication succeeded (" + method + ").", true);
                        } catch (ProxyAuthCancelException ee) {
                            auth_cancel = true;
                        } catch (ProxyPartialAuthException ee) {
                            String tmp = smethods;
                            smethods = ee.getMethods();
                            smethoda = Tools.split(smethods, ",");
                            if (!tmp.equals(smethods)) {
                                methodi = 0;
                            }

                            //System.err.println("PartialAuth: "+methods);
                            auth_cancel = false;
                            continue loop;
                        } catch (RuntimeException ee) {
                            throw ee;
                        } catch (ProxyException ee) {
                            throw ee;
                        } catch (Exception ee) {
                            //System.err.println("ee: "+ee); // SSH_MSG_DISCONNECT: 2 Too many authentication failures
                            Logs.Println(proxy.Logger.WARN,
                                    "an exception during authentication\n" + ee.toString(), true);
                            break loop;
                        }
                    }
                }
                break;
            }

            if (!auth) {
                if (auth_failures >= max_auth_tries) {
                    Logs.Println(proxy.Logger.INFO,
                            "Login trials exceeds " + max_auth_tries, true);
                }
                if (auth_cancel) {
                    throw new ProxyException("Auth cancel");
                }
                throw new ProxyException("Auth fail");
            }

            isAuthed = true;
            Logs.Println(proxy.Logger.INFO, "Connect success to Linux remotehost " + remotehost, true);
            return true;
        } catch (Exception e) {
            in_kex = false;
            try {

                if (isConnected) {
                    String message = e.toString();
                    disconnectpacket(message);
                }
            } catch (Exception ee) {
            }
            try {
                disconnect();
                return false;
            } catch (Exception ee) {
            }
            isConnected = false;
            //e.printStackTrace();
            if (e instanceof RuntimeException) {
                throw (RuntimeException) e;
            }
            if (e instanceof ProxyException) {
                throw (ProxyException) e;
            }
            throw new ProxyException("Session.connect: " + e);
        } finally {
            Tools.bzero(this.passwordSSH);
            this.passwordSSH = null;
        }

    }

    ////////////////////////////////////////////////////////////////////////////
    ////////////////////////////////////////////////////////////////////////////
    ////////////////////////////////////////////////////////////////////////////
    private KeyExchangelinux receive_kexinit(Buffer buf) throws Exception {
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

        guess = KeyExchangelinux.guess(I_S, I_C);
        if (guess == null) {
            throw new ProxyException("Algorithm negotiation fail");
        }

        if (!isAuthed
                && (guess[KeyExchangelinux.PROPOSAL_ENC_ALGS_CTOS].equals("none")
                || (guess[KeyExchangelinux.PROPOSAL_ENC_ALGS_STOC].equals("none")))) {
            throw new ProxyException("NONE Cipher should not be chosen before authentification is successed.");
        }

        KeyExchangelinux kex = null;
        try {
            Class c = Class.forName(getConfig(guess[KeyExchangelinux.PROPOSAL_KEX_ALGS]));
            kex = (KeyExchangelinux) (c.newInstance());
        } catch (Exception e) {
            throw new ProxyException(e.toString(), e);
        }

        kex.init(this, V_S, V_C, I_S, I_C);
        return kex;
    }

    private volatile boolean in_kex = false;

    public void rekey() throws Exception {
        send_kexinit();
    }

    private void send_kexinit() throws Exception {
        if (in_kex) {
            return;
        }

        String cipherc2s = getConfig("cipher.c2s");
        String ciphers2c = getConfig("cipher.s2c");

        String[] not_available_ciphers = checkCiphers(getConfig("CheckCiphers"));
        if (not_available_ciphers != null && not_available_ciphers.length > 0) {
            cipherc2s = Tools.diffString(cipherc2s, not_available_ciphers);
            ciphers2c = Tools.diffString(ciphers2c, not_available_ciphers);
            if (cipherc2s == null || ciphers2c == null) {
                throw new ProxyException("There are not any available ciphers.");
            }
        }

        String kex = getConfig("kex");
        String[] not_available_kexes = checkKexes(getConfig("CheckKexes"));
        if (not_available_kexes != null && not_available_kexes.length > 0) {
            kex = Tools.diffString(kex, not_available_kexes);
            if (kex == null) {
                throw new ProxyException("There are not any available kexes.");
            }
        }

        String server_host_key = getConfig("server_host_key");
        String[] not_available_shks
                = checkSignatures(getConfig("CheckSignatures"));
        if (not_available_shks != null && not_available_shks.length > 0) {
            server_host_key = Tools.diffString(server_host_key, not_available_shks);
            if (server_host_key == null) {
                throw new ProxyException("There are not any available sig algorithm.");
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
        synchronized (random) {
            random.fill(buf.buffer, buf.index, 16);
            buf.skip(16);
        }
        buf.putString(Tools.str2byte(kex));
        buf.putString(Tools.str2byte(server_host_key));
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

        buf.setOffSet(5);
        I_C = new byte[buf.getLength()];
        buf.getByte(I_C);

        write(packet);

        Logs.Println(proxy.Logger.INFO,
                "SSH_MSG_KEXINIT sent", true);
    }

    private void send_newkeys() throws Exception {
        // send SSH_MSG_NEWKEYS(21)
        packet.reset();
        buf.putByte((byte) SSH_MSG_NEWKEYS);
        write(packet);
        Logs.Println(proxy.Logger.INFO,
                "SSH_MSG_NEWKEYS sent", true);
    }

    int[] uncompress_len = new int[1];
    int[] compress_len = new int[1];

    private int s2ccipher_size = 8;
    private int c2scipher_size = 8;

    private void start_discard(Buffer buf, Cipher cipher, MAC mac,
            int packet_length, int discard) throws ProxyException, IOException {
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
            iolinux.getByte(buf.buffer, 0, len);
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

    byte[] getSessionId() {
        return session_id;
    }

    private void receive_newkeys(Buffer buf, KeyExchangelinux kex) throws Exception {
        updateKeys(kex);
        in_kex = false;
    }

    private void updateKeys(KeyExchangelinux kex) throws Exception {
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

            method = guess[KeyExchangelinux.PROPOSAL_ENC_ALGS_STOC];
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

            method = guess[KeyExchangelinux.PROPOSAL_MAC_ALGS_STOC];
            c = Class.forName(getConfig(method));
            s2cmac = (MAC) (c.newInstance());
            MACs2c = expandKey(buf, K, H, MACs2c, hash, s2cmac.getBlockSize());
            s2cmac.init(MACs2c);
            //mac_buf=new byte[s2cmac.getBlockSize()];
            s2cmac_result1 = new byte[s2cmac.getBlockSize()];
            s2cmac_result2 = new byte[s2cmac.getBlockSize()];

            method = guess[KeyExchangelinux.PROPOSAL_ENC_ALGS_CTOS];
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

            method = guess[KeyExchangelinux.PROPOSAL_MAC_ALGS_CTOS];
            c = Class.forName(getConfig(method));
            c2smac = (MAC) (c.newInstance());
            MACc2s = expandKey(buf, K, H, MACc2s, hash, c2smac.getBlockSize());
            c2smac.init(MACc2s);

            method = guess[KeyExchangelinux.PROPOSAL_COMP_ALGS_CTOS];
            initDeflater(method);

            method = guess[KeyExchangelinux.PROPOSAL_COMP_ALGS_STOC];
            initInflater(method);
        } catch (Exception e) {
            if (e instanceof ProxyException) {
                throw e;
            }
            throw new ProxyException(e.toString(), e);
            //System.err.println("updatekeys: "+e); 
        }
    }

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

    ////////////////////////////////////////////////////////////////////////////
    public Buffer read(Buffer buf) throws Exception {
        int j = 0;
        while (true) {
            buf.reset();
            iolinux.getByte(buf.buffer, buf.index, s2ccipher_size);
            buf.index += s2ccipher_size;
            if (s2ccipher != null) {
                s2ccipher.update(buf.buffer, 0, s2ccipher_size, buf.buffer, 0);
            }
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
                Logs.Println(proxy.Logger.INFO, message, true);
                start_discard(buf, s2ccipher, s2cmac, j, PACKET_MAX_SIZE - s2ccipher_size);
            }

            if (need > 0) {
                iolinux.getByte(buf.buffer, buf.index, need);
                buf.index += (need);
                if (s2ccipher != null) {
                    s2ccipher.update(buf.buffer, s2ccipher_size, need, buf.buffer, s2ccipher_size);
                }
            }

            if (s2cmac != null) {
                s2cmac.update(seqi);
                s2cmac.update(buf.buffer, 0, buf.index);

                s2cmac.doFinal(s2cmac_result1, 0);
                iolinux.getByte(s2cmac_result2, 0, s2cmac_result2.length);
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
            //System.err.println("LINUX [ nhan ] LtoS: " + type); // NHo xoa cho nay

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
                Logs.Println(proxy.Logger.INFO,
                        "Received SSH_MSG_UNIMPLEMENTED for " + reason_id, true);
            } else if (type == SSH_MSG_DEBUG) {
                buf.rewind();
                buf.getInt();
                buf.getShort();
                /*
                 byte always_display=(byte)buf.getByte();
                 byte[] message=buf.getString();
                 byte[] language_tag=buf.getString();
                 System.err.println("SSH_MSG_DEBUG:"+
                 " "+Tools.byte2str(message)+
                 " "+Tools.byte2str(language_tag));
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

    public void write(Packet packet) throws Exception {
//        System.err.println(packet.buffer.getCommand());
//        System.err.println(packet.buffer.index);
        long t = getTimeout();
        while (in_kex) {
            if (t > 0L && (System.currentTimeMillis() - kex_start_time) > t) {
                throw new ProxyException("timeout in wating for rekeying process.");
            }
            byte command = packet.buffer.getCommand();

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

    public void _write(Packet packet) throws Exception {
        synchronized (parent) {
            encode(packet);
            if (iolinux != null) {
                iolinux.put(packet);
                seqo++;
            }
        }

    }

    public void encode(Packet packet) throws Exception {

        if (deflater != null) {

            compress_len[0] = packet.buffer.index;
            packet.buffer.buffer = deflater.compress(packet.buffer.buffer,
                    5, compress_len);
            packet.buffer.index = compress_len[0];
        }

        if (c2scipher != null) {

            //packet.padding(c2scipher.getIVSize());
            packet.padding(c2scipher_size);
            int pad = packet.buffer.buffer[4];
            synchronized (random) {
                random.fill(packet.buffer.buffer, packet.buffer.index - pad, pad);
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

    ////////////////////////////////////////////////////////////////////////////
    ////////////////////////////////////////////////////////////////////////////
    ////////////////////////////////////////////////////////////////////////////
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
    //-------------------------------------

    public void disconnect() {
        if (!isConnected) {
            return;
        }
        //System.err.println(this+": disconnect");
        //Thread.dumpStack();

        isConnected = false;

        try {
            if (iolinux != null) {
                if (iolinux.in != null) {
                    iolinux.in.close();
                }
                if (iolinux.out != null) {
                    iolinux.out.close();
                }
                if (iolinux.out_ext != null) {
                    iolinux.out_ext.close();
                }
            }
        } catch (Exception e) {
//      e.printStackTrace();
        }
        iolinux = null;
        socket = null;
//    synchronized(jsch.pool){
//      jsch.pool.removeElement(this);
//    }
        _proxy.Close();
        //System.gc();
    }

    ////////////////////////////////////////////////////////////////////////////
    private void setStream() {
        synchronized (parent) {
            try {
                //Linux
                socket = _proxy.LinuxSocket;
                //socket = proxy.Tools.createSocket(remotehost, port, 0);
                inlinux = socket.getInputStream();
                outlinux = socket.getOutputStream();

                //socket.setTcpNoDelay(true);
                iolinux.setInputStream(inlinux);
                iolinux.setOutputStream(outlinux);

            } catch (Exception e) {
                System.err.println(e.toString());
            }
        }
    }

    public boolean isConnected() {
        return isConnected;
    }

    public IO getiolinux() {
        return iolinux;
    }

    public void setConfig(java.util.Properties newconf) {
        setConfig((java.util.Hashtable) newconf);
    }

    public void setConfig(java.util.Hashtable newconf) {
        synchronized (parent) {
            if (config == null) {
                config = new java.util.Hashtable();
            }
            for (java.util.Enumeration e = newconf.keys(); e.hasMoreElements();) {
                String key = (String) (e.nextElement());
                config.put(key, (String) (newconf.get(key)));
            }
        }
    }

    public void setConfig(String key, String value) {
        synchronized (parent) {
            if (config == null) {
                config = new java.util.Hashtable();
            }
            config.put(key, value);
        }
    }

    public String getConfig(String key) {
        Object foo = null;
        if (config != null) {
            foo = config.get(key);
            if (foo instanceof String) {
                return (String) foo;
            }
        }
        foo = ConfigureClient.getConfig(key);
        if (foo instanceof String) {
            return (String) foo;
        }
        return null;
    }

    public int getTimeout() {
        return timeout;
    }

    public void setTimeout(int timeout) throws ProxyException {
        if (socket == null) {
            if (timeout < 0) {
                throw new ProxyException("invalid timeout value");
            }
            this.timeout = timeout;
            return;
        }
        try {
            socket.setSoTimeout(timeout);
            this.timeout = timeout;
        } catch (Exception e) {
            if (e instanceof Throwable) {
                throw new ProxyException(e.toString(), (Throwable) e);
            }
            throw new ProxyException(e.toString());
        }
    }

    public String getServerVersion() {
        return Tools.byte2str(V_S);
    }

    public String getClientVersion() {
        return Tools.byte2str(V_C);
    }

    public void setClientVersion(String cv) {
        V_C = Tools.str2byte(cv);
    }

    public void sendIgnore() throws Exception {
        Buffer buf = new Buffer();
        Packet packet = new Packet(buf);
        packet.reset();
        buf.putByte((byte) SSH_MSG_IGNORE);
        write(packet);
    }

    public String getRemoteHost() {
        return remotehost;
    }

    public String getUserName() {
        return usernameSSH;
    }

    public int getPort() {
        return port;
    }

    public void setProxy(proxy.Proxy proxy) {
        this.parent = proxy;
    }

    public void setHost(String host) {
        this.remotehost = host;
    }

    public void setPort(int port) {
        this.port = port;
    }

    public void setUserName(String username) {
        this.usernameSSH = username;
    }

    public void setPassword(String password) {
        if (password != null) {
            setPassword(Tools.str2byte(password));
        }

    }

    void setPassword(byte[] password) {
        if (password != null) {
            this.passwordSSH = new byte[password.length];
            System.arraycopy(password, 0, this.passwordSSH, 0, password.length);
        }
    }

    ////////////////////////////////////////////////////////////////////////////
    private String[] checkCiphers(String ciphers) {
        if (ciphers == null || ciphers.length() == 0) {
            return null;
        }

        String cipherc2s = getConfig("cipher.c2s");
        String ciphers2c = getConfig("cipher.s2c");

        Vector result = new Vector();
        String[] _ciphers = Tools.split(ciphers, ",");
        for (int i = 0; i < _ciphers.length; i++) {
            String cipher = _ciphers[i];
            if (ciphers2c.indexOf(cipher) == -1 && cipherc2s.indexOf(cipher) == -1) {
                continue;
            }
            if (!checkCipher(getConfig(cipher))) {
                result.addElement(cipher);
            }
        }
        if (result.size() == 0) {
            return null;
        }
        String[] foo = new String[result.size()];
        System.arraycopy(result.toArray(), 0, foo, 0, result.size());

        return foo;
    }

    static boolean checkCipher(String cipher) {
        try {
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

    private String[] checkKexes(String kexes) {
        if (kexes == null || kexes.length() == 0) {
            return null;
        }

        java.util.Vector result = new java.util.Vector();
        String[] _kexes = Tools.split(kexes, ",");
        for (int i = 0; i < _kexes.length; i++) {
            if (!checkKex(this, getConfig(_kexes[i]))) {
                result.addElement(_kexes[i]);
            }
        }
        if (result.size() == 0) {
            return null;
        }
        String[] foo = new String[result.size()];
        System.arraycopy(result.toArray(), 0, foo, 0, result.size());

        return foo;
    }

    static boolean checkKex(sshLinux s, String kex) {
        try {
            Class c = Class.forName(kex);
            KeyExchangelinux _c = (KeyExchangelinux) (c.newInstance());
            _c.init(s, null, null, null, null);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private String[] checkSignatures(String sigs) {
        if (sigs == null || sigs.length() == 0) {
            return null;
        }

        java.util.Vector result = new java.util.Vector();
        String[] _sigs = Tools.split(sigs, ",");
        for (int i = 0; i < _sigs.length; i++) {
            try {
                Class c = Class.forName((String) ConfigureClient.getConfig(_sigs[i]));
                final Signature sig = (Signature) (c.newInstance());
                sig.init();
            } catch (Exception e) {
                result.addElement(_sigs[i]);
            }
        }
        if (result.size() == 0) {
            return null;
        }
        String[] foo = new String[result.size()];
        System.arraycopy(result.toArray(), 0, foo, 0, result.size());
        return foo;
    }

    private void checkConfig(ConfigRepository.Config config, String key) {
        String value = config.getValue(key);
        if (value != null) {
            this.setConfig(key, value);
        }
    }

    ////////////////////////////////////////////////////////////////////////////
    @Override
    public void run() {

    }
}
