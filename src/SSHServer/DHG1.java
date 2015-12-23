package SSHServer;

import java.math.BigInteger;
import proxy.Tools;

public class DHG1 extends SSHServer.KeyExchange {

    static final byte[] g = {2};
    static final byte[] p = {
        (byte) 0x00,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xC9, (byte) 0x0F, (byte) 0xDA, (byte) 0xA2, (byte) 0x21, (byte) 0x68, (byte) 0xC2, (byte) 0x34,
        (byte) 0xC4, (byte) 0xC6, (byte) 0x62, (byte) 0x8B, (byte) 0x80, (byte) 0xDC, (byte) 0x1C, (byte) 0xD1,
        (byte) 0x29, (byte) 0x02, (byte) 0x4E, (byte) 0x08, (byte) 0x8A, (byte) 0x67, (byte) 0xCC, (byte) 0x74,
        (byte) 0x02, (byte) 0x0B, (byte) 0xBE, (byte) 0xA6, (byte) 0x3B, (byte) 0x13, (byte) 0x9B, (byte) 0x22,
        (byte) 0x51, (byte) 0x4A, (byte) 0x08, (byte) 0x79, (byte) 0x8E, (byte) 0x34, (byte) 0x04, (byte) 0xDD,
        (byte) 0xEF, (byte) 0x95, (byte) 0x19, (byte) 0xB3, (byte) 0xCD, (byte) 0x3A, (byte) 0x43, (byte) 0x1B,
        (byte) 0x30, (byte) 0x2B, (byte) 0x0A, (byte) 0x6D, (byte) 0xF2, (byte) 0x5F, (byte) 0x14, (byte) 0x37,
        (byte) 0x4F, (byte) 0xE1, (byte) 0x35, (byte) 0x6D, (byte) 0x6D, (byte) 0x51, (byte) 0xC2, (byte) 0x45,
        (byte) 0xE4, (byte) 0x85, (byte) 0xB5, (byte) 0x76, (byte) 0x62, (byte) 0x5E, (byte) 0x7E, (byte) 0xC6,
        (byte) 0xF4, (byte) 0x4C, (byte) 0x42, (byte) 0xE9, (byte) 0xA6, (byte) 0x37, (byte) 0xED, (byte) 0x6B,
        (byte) 0x0B, (byte) 0xFF, (byte) 0x5C, (byte) 0xB6, (byte) 0xF4, (byte) 0x06, (byte) 0xB7, (byte) 0xED,
        (byte) 0xEE, (byte) 0x38, (byte) 0x6B, (byte) 0xFB, (byte) 0x5A, (byte) 0x89, (byte) 0x9F, (byte) 0xA5,
        (byte) 0xAE, (byte) 0x9F, (byte) 0x24, (byte) 0x11, (byte) 0x7C, (byte) 0x4B, (byte) 0x1F, (byte) 0xE6,
        (byte) 0x49, (byte) 0x28, (byte) 0x66, (byte) 0x51, (byte) 0xEC, (byte) 0xE6, (byte) 0x53, (byte) 0x81,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF
    };

    private static final int SSH_MSG_KEXDH_INIT = 30;
    private static final int SSH_MSG_KEXDH_REPLY = 31;
    static final int SSH_MSG_NEWKEYS = 21;
    private static final int SSH_MSG_KEX_DH_GEX_REQUEST = 34;
    static final int RSA = 0;
    static final int DSS = 1;
    private int type = 0;

    private int state;

    DH dh;
    KeyPair keyrsa;

//  HASH sha;
//  byte[] K;
//  byte[] H;
    byte[] V_S;
    byte[] V_C;
    byte[] I_S;
    byte[] I_C;

    byte[] K_S;
    byte[] e;
    byte[] f;
    private Buffer buf;
    private Packet packet;
    private Configure configure;
    private KeyPair keypair;
////////////////////////////////////////////////////////////////////////////////

    public void init(sshServer session,
            byte[] V_S, byte[] V_C, byte[] I_S, byte[] I_C) throws Exception {
        this.session = session;
        this.V_S = V_S;
        this.V_C = V_C;
        this.I_S = I_S;
        this.I_C = I_C;
        buf = new Buffer();
        packet = new Packet(buf);

        //-----------------------------
        try {
            Class c = Class.forName(session.getConfig("sha-1"));
            sha = (HASH) (c.newInstance());
            sha.init();
        } catch (Exception ee) {
            
        }

        try {
            Class c = Class.forName(session.getConfig("dh"));
            dh = (DH) (c.newInstance());
            dh.init();
        } catch (Exception ee) {
            
        }
        keypair = KeyPair.load(configure, "key\\proxyprv", "key\\proxypub.pub");
        
//        keypair = KeyPair.genKeyPair(configure, 2, 2048);
//        String passphare = "proxyssh";
//        keypair.writePublicKey("key\\proxypub.pub", "");
//        keypair.writePrivateKey("key\\proxyprv");
        
        buf.reset();
        buf.putByte(keypair.getPublicKeyBlob());
        K_S = new byte[buf.index];
        System.arraycopy(buf.buffer, 0, K_S, 0, buf.index);

        //--------------------------------------------
        buf.reset();
        buf = session.read(buf);
        int pack_len = buf.getInt();
        int pad = buf.getByte();
        int commmand = buf.getByte();
        e = buf.getMPInt();

        //------------------------------------
        dh.setP(p);
        dh.setG(g);
        f = dh.getE();
        dh.setF(e);
        dh.checkRange();
        K = normalize(dh.getK());

        //------------------------------------        
        //make H
        buf.reset();
        buf.putString(V_C);
        buf.putString(V_S);
        buf.putString(I_S);
        buf.putString(I_C);
        buf.putString(K_S);
        buf.putMPInt(e);
        buf.putMPInt(f);
        buf.putMPInt(K);
        sha.update(buf.buffer,0, buf.index);
        H = sha.digest();
        byte[] signH = keypair.getSignature(H);

        //================================================
//        System.out.println("V_C:(Version Client)   " + proxy.Tools.byte2str(V_C));
//        System.out.println("V_S:(Version sshServer)   " + proxy.Tools.byte2str(V_S));
//        System.out.println("I_C:(data    Client)   " + proxy.Tools.byte2str(I_C));
//        System.out.println("I_S:(data    sshServer)   " + proxy.Tools.byte2str(I_S));
//        StringBuffer sb = new StringBuffer();
//        for (byte b : K_S) {
//            sb.append(Integer.toHexString((int) (b & 0xff)));
//        }
//        System.out.println("K_S       :" + sb.toString());
//
//        sb = new StringBuffer();
//        for (byte b : e) {
//            sb.append(Integer.toHexString((int) (b & 0xff)));
//        }
//        System.out.println("E :       :" + sb.toString());
//
//        sb = new StringBuffer();
//        for (byte b : f) {
//            sb.append(Integer.toHexString((int) (b & 0xff)));
//        }
//        System.out.println("F         :" + sb.toString());
//
//        StringBuffer sb = new StringBuffer();
//        for (byte b : K) {
//            sb.append(Integer.toHexString((int) (b & 0xff)));
//        }
//        System.out.println("K         :" + sb.toString());
//
//        sb = new StringBuffer();
//        for (byte b : H) {
//            sb.append(Integer.toHexString((int) (b & 0xff)));
//        }
//        System.out.println("H         :" + sb.toString());
//
//        sb = new StringBuffer();
//        for (byte b : signH) {
//            sb.append(Integer.toHexString((int) (b & 0xff)));
//        }
//        System.out.println("signH     :" + sb.toString());
        //================================================
        buf.reset();
        packet.reset();
        buf.putByte((byte) SSH_MSG_KEXDH_REPLY );
        buf.putString(K_S);
        buf.putMPInt(f);
        buf.putString(signH);
        session.write(packet);
        proxy.Logs.Println(proxy.Logger.INFO,"SSH_MSG_KEXDH_REPLY sent",true);
        
    }

    public boolean next(Buffer _buf) throws Exception {
        return true;
    }

    public String getKeyType() {
        if (type == DSS) {
            return "DSA";
        }
        return "RSA";
    }

    public int getState() {
        return state;
    }

 
}
