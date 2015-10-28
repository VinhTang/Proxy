/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package ssh;

/**
 *
 * @author Milky_Way
 */
public class Configure {

    static java.util.Hashtable config = new java.util.Hashtable();

    static {
//  config.put("kex", "diffie-hellman-group-exchange-sha1");
        config.put("kex", "diffie-hellman-group1-sha1,diffie-hellman-group-exchange-sha1");
        config.put("server_host_key", "ssh-rsa,ssh-dss");
//    config.put("server_host_key", "ssh-dss,ssh-rsa");

        config.put("cipher.s2c",
                "aes128-ctr,aes128-cbc,3des-ctr,3des-cbc,blowfish-cbc,aes192-cbc,aes256-cbc");
        config.put("cipher.c2s",
                "aes128-ctr,aes128-cbc,3des-ctr,3des-cbc,blowfish-cbc,aes192-cbc,aes256-cbc");

        config.put("mac.s2c", "hmac-md5,hmac-sha1,hmac-sha1-96,hmac-md5-96");
        config.put("mac.c2s", "hmac-md5,hmac-sha1,hmac-sha1-96,hmac-md5-96");
        config.put("compression.s2c", "none");
        // config.put("compression.s2c", "zlib@openssh.com,zlib,none");
        config.put("compression.c2s", "none");
        // config.put("compression.c2s", "zlib@openssh.com,zlib,none");

        config.put("lang.s2c", "");
        config.put("lang.c2s", "");

        config.put("compression_level", "6");

        config.put("diffie-hellman-group-exchange-sha1",
                "com.jcraft.jsch.DHGEX");
        config.put("diffie-hellman-group1-sha1",
                "com.jcraft.jsch.DHG1");

        config.put("dh", "com.jcraft.jsch.jce.DH");
        config.put("3des-cbc", "com.jcraft.jsch.jce.TripleDESCBC");
        config.put("blowfish-cbc", "com.jcraft.jsch.jce.BlowfishCBC");
        config.put("hmac-sha1", "com.jcraft.jsch.jce.HMACSHA1");
        config.put("hmac-sha1-96", "com.jcraft.jsch.jce.HMACSHA196");
        config.put("hmac-md5", "com.jcraft.jsch.jce.HMACMD5");
        config.put("hmac-md5-96", "com.jcraft.jsch.jce.HMACMD596");
        config.put("sha-1", "com.jcraft.jsch.jce.SHA1");
        config.put("md5", "com.jcraft.jsch.jce.MD5");
        config.put("signature.dss", "com.jcraft.jsch.jce.SignatureDSA");
        config.put("signature.rsa", "com.jcraft.jsch.jce.SignatureRSA");
        config.put("keypairgen.dsa", "com.jcraft.jsch.jce.KeyPairGenDSA");
        config.put("keypairgen.rsa", "com.jcraft.jsch.jce.KeyPairGenRSA");
        config.put("random", "com.jcraft.jsch.jce.Random");

        config.put("none", "com.jcraft.jsch.CipherNone");

        config.put("aes128-cbc", "com.jcraft.jsch.jce.AES128CBC");
        config.put("aes192-cbc", "com.jcraft.jsch.jce.AES192CBC");
        config.put("aes256-cbc", "com.jcraft.jsch.jce.AES256CBC");

        config.put("aes128-ctr", "com.jcraft.jsch.jce.AES128CTR");
        config.put("aes192-ctr", "com.jcraft.jsch.jce.AES192CTR");
        config.put("aes256-ctr", "com.jcraft.jsch.jce.AES256CTR");
        config.put("3des-ctr", "com.jcraft.jsch.jce.TripleDESCTR");
        config.put("arcfour", "com.jcraft.jsch.jce.ARCFOUR");
        config.put("arcfour128", "com.jcraft.jsch.jce.ARCFOUR128");
        config.put("arcfour256", "com.jcraft.jsch.jce.ARCFOUR256");

        config.put("userauth.none", "com.jcraft.jsch.UserAuthNone");
        config.put("userauth.password", "com.jcraft.jsch.UserAuthPassword");
        config.put("userauth.keyboard-interactive", "com.jcraft.jsch.UserAuthKeyboardInteractive");
        config.put("userauth.publickey", "com.jcraft.jsch.UserAuthPublicKey");
        config.put("userauth.gssapi-with-mic", "com.jcraft.jsch.UserAuthGSSAPIWithMIC");
        config.put("gssapi-with-mic.krb5", "com.jcraft.jsch.jgss.GSSContextKrb5");

        config.put("zlib", "com.jcraft.jsch.jcraft.Compression");
        config.put("zlib@openssh.com", "com.jcraft.jsch.jcraft.Compression");

        config.put("StrictHostKeyChecking", "ask");
        config.put("HashKnownHosts", "no");
        //config.put("HashKnownHosts",  "yes");
        config.put("PreferredAuthentications", "gssapi-with-mic,publickey,keyboard-interactive,password");

        config.put("CheckCiphers", "aes256-ctr,aes192-ctr,aes128-ctr,aes256-cbc,aes192-cbc,aes128-cbc,3des-ctr,arcfour,arcfour128,arcfour256");
    }
    java.util.Vector pool = new java.util.Vector();
    java.util.Vector identities = new java.util.Vector();
    //private HostKeyRepository known_hosts = null;

//    private static final Logger DEVNULL = new Logger() {
//        public boolean isEnabled(int level) {
//            return false;
//        }
//
//        public void log(int level, String message) {
//        }
//    };
//    static Logger logger = DEVNULL;

    public Configure() {

        try {
            String osname = (String) (System.getProperties().get("os.name"));
            if (osname != null && osname.equals("Mac OS X")) {
                config.put("hmac-sha1", "com.jcraft.jsch.jcraft.HMACSHA1");
                config.put("hmac-md5", "com.jcraft.jsch.jcraft.HMACMD5");
                config.put("hmac-md5-96", "com.jcraft.jsch.jcraft.HMACMD596");
                config.put("hmac-sha1-96", "com.jcraft.jsch.jcraft.HMACSHA196");
            }
        } catch (Exception e) {
        }

    }



    public static String getConfig(String key) {
        synchronized (config) {
            return (String) (config.get(key));
        }
    }

    public static void setConfig(java.util.Hashtable newconf) {
        synchronized (config) {
            for (java.util.Enumeration e = newconf.keys(); e.hasMoreElements();) {
                String key = (String) (e.nextElement());
                config.put(key, (String) (newconf.get(key)));
            }
        }
    }

    public static void setConfig(String key, String value) {
        config.put(key, value);
    }

}
