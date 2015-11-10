package ssh;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
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
                "jcraft.DHGEX");
        config.put("diffie-hellman-group1-sha1", "ssh.DHG1");

        config.put("dh", "jce.DH");
        config.put("3des-cbc", "jce.TripleDESCBC");
        config.put("blowfish-cbc", "jce.BlowfishCBC");
        config.put("hmac-sha1", "jce.HMACSHA1");
        config.put("hmac-sha1-96", "jce.HMACSHA196");
        config.put("hmac-md5", "jce.HMACMD5");
        config.put("hmac-md5-96", "jce.HMACMD596");
        config.put("sha-1", "jce.SHA1");
        config.put("md5", "jce.MD5");
        config.put("signature.dss", "jce.SignatureDSA");
        config.put("signature.rsa", "jce.SignatureRSA");
        config.put("keypairgen.dsa", "jce.KeyPairGenDSA");
        config.put("keypairgen.rsa", "jce.KeyPairGenRSA");
        config.put("random", "jce.Random");

        config.put("none", "jcraft.CipherNone");

        config.put("aes128-cbc", "jce.AES128CBC");
        config.put("aes192-cbc", "jce.AES192CBC");
        config.put("aes256-cbc", "jce.AES256CBC");

        config.put("aes128-ctr", "jce.AES128CTR");
        config.put("aes192-ctr", "jce.AES192CTR");
        config.put("aes256-ctr", "jce.AES256CTR");
        config.put("3des-ctr", "jce.TripleDESCTR");
        config.put("arcfour", "jce.ARCFOUR");
        config.put("arcfour128", "jce.ARCFOUR128");
        config.put("arcfour256", "jce.ARCFOUR256");

        config.put("userauth.none", "jcraft.UserAuthNone");
        config.put("userauth.password", "jcraft.UserAuthPassword");
        config.put("userauth.keyboard-interactive", "jcraft.UserAuthKeyboardInteractive");
        config.put("userauth.publickey", "jcraft.UserAuthPublicKey");
        config.put("userauth.gssapi-with-mic", "jcraft.UserAuthGSSAPIWithMIC");
        config.put("gssapi-with-mic.krb5", "jcraft.jgss.GSSContextKrb5");

        config.put("zlib", "jcraft.jcraft.Compression");
        config.put("zlib@openssh.com", "jcraft.jcraft.Compression");

        config.put("StrictHostKeyChecking", "ask");
        config.put("HashKnownHosts", "no");
        //config.put("HashKnownHosts",  "yes");
        config.put("PreferredAuthentications", "gssapi-with-mic,publickey,keyboard-interactive,password");

        config.put("CheckCiphers", "aes256-ctr,aes192-ctr,aes128-ctr,aes256-cbc,aes192-cbc,aes128-cbc,3des-ctr,arcfour,arcfour128,arcfour256");
    }
    java.util.Vector pool = new java.util.Vector();
    java.util.Vector identities = new java.util.Vector();
    
    private HostKeyRepository known_hosts = null;
    

    public Configure() {

        try {
            String osname = (String) (System.getProperties().get("os.name"));

            if (osname != null && osname.equals("Mac OS X")) {
                config.put("hmac-sha1", "jcraft.jcraft.HMACSHA1");
                config.put("hmac-md5", "jcraft.jcraft.HMACMD5");
                config.put("hmac-md5-96", "jcraft.jcraft.HMACMD596");
                config.put("hmac-sha1-96", "jcraft.jcraft.HMACSHA196");
            }
        } catch (Exception e) {
        }

    }

    public HostKeyRepository getHostKeyRepository() {
        if (known_hosts == null) {
            known_hosts = new KnownHosts(this);
        }
        return known_hosts;
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

    public static String getConfig(String key) {
        synchronized (config) {
            return (String) (config.get(key));
        }
    }

}
