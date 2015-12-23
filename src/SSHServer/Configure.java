/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package SSHServer;

import java.io.InputStream;
import java.util.Vector;

public class Configure {

    /**
     * The version number.
     */
    public static final String VERSION = "0.1.53";

    static java.util.Hashtable config = new java.util.Hashtable();

    static {

        config.put("kex", "diffie-hellman-group1-sha1");
        //--------------only 1 algs can choose------------------------
        config.put("server_host_key", "ssh-rsa");
        config.put("cipher.s2c", "aes128-ctr");
        config.put("cipher.c2s", "aes128-ctr");
        config.put("mac.s2c", "hmac-sha1");
        config.put("mac.c2s", "hmac-sha1");
        config.put("compression.s2c", "none");
        config.put("compression.c2s", "none");
        //------------------------------------------------------------
//        config.put("server_host_key", "ssh-rsa,ssh-dss,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521");
//        config.put("cipher.s2c",
//                "aes128-ctr,aes128-cbc,3des-ctr,3des-cbc,blowfish-cbc,aes192-ctr,aes192-cbc,aes256-ctr,aes256-cbc");
//        config.put("cipher.c2s",
//                "aes128-ctr,aes128-cbc,3des-ctr,3des-cbc,blowfish-cbc,aes192-ctr,aes192-cbc,aes256-ctr,aes256-cbc");
//
//        config.put("mac.s2c", "hmac-md5,hmac-sha1,hmac-sha2-256,hmac-sha1-96,hmac-md5-96");
//        config.put("mac.c2s", "hmac-md5,hmac-sha1,hmac-sha2-256,hmac-sha1-96,hmac-md5-96");
        //------------------------------------------------------------
        config.put("compression.s2c", "none");
        config.put("compression.c2s", "none");

        config.put("lang.s2c", "");
        config.put("lang.c2s", "");

        config.put("compression_level", "6");

        config.put("diffie-hellman-group-exchange-sha1",
                "SSHServer.DHGEX");
        config.put("diffie-hellman-group1-sha1",
                "SSHServer.DHG1");
        config.put("diffie-hellman-group14-sha1",
                "SSHServer.DHG14");    // available since JDK8.
        config.put("diffie-hellman-group-exchange-sha256",
                "SSHServer.DHGEX256"); // available since JDK1.4.2.
        // On JDK8, 2048bits will be used.
        config.put("ecdsa-sha2-nistp256", "SSHServer.jce.SignatureECDSA");
        config.put("ecdsa-sha2-nistp384", "SSHServer.jce.SignatureECDSA");
        config.put("ecdsa-sha2-nistp521", "SSHServer.jce.SignatureECDSA");

        config.put("ecdh-sha2-nistp256", "SSHServer.DHEC256");
        config.put("ecdh-sha2-nistp384", "SSHServer.DHEC384");
        config.put("ecdh-sha2-nistp521", "SSHServer.DHEC521");

        config.put("ecdh-sha2-nistp", "SSHServer.jce.ECDHN");

        config.put("dh", "SSHServer.jce.DH");
        config.put("3des-cbc", "SSHServer.jce.TripleDESCBC");
        config.put("blowfish-cbc", "SSHServer.jce.BlowfishCBC");
        config.put("hmac-sha1", "SSHServer.jce.HMACSHA1");
        config.put("hmac-sha1-96", "SSHServer.jce.HMACSHA196");
        config.put("hmac-sha2-256", "SSHServer.jce.HMACSHA256");

        config.put("hmac-md5", "SSHServer.jce.HMACMD5");
        config.put("hmac-md5-96", "SSHServer.jce.HMACMD596");
        config.put("sha-1", "SSHServer.jce.SHA1");
        config.put("sha-256", "SSHServer.jce.SHA256");
        config.put("sha-384", "SSHServer.jce.SHA384");
        config.put("sha-512", "SSHServer.jce.SHA512");
        config.put("md5", "SSHServer.jce.MD5");
        config.put("signature.dss", "SSHServer.jce.SignatureDSA");
        config.put("signature.rsa", "SSHServer.jce.SignatureRSA");
        config.put("signature.ecdsa", "SSHServer.jce.SignatureECDSA");
        config.put("keypairgen.dsa", "SSHServer.jce.KeyPairGenDSA");
        config.put("keypairgen.rsa", "SSHServer.jce.KeyPairGenRSA");
        config.put("keypairgen.ecdsa", "SSHServer.jce.KeyPairGenECDSA");
        config.put("random", "SSHServer.jce.Random");

        config.put("none", "SSHServer.CipherNone");

        config.put("aes128-cbc", "SSHServer.jce.AES128CBC");
        config.put("aes192-cbc", "SSHServer.jce.AES192CBC");
        config.put("aes256-cbc", "SSHServer.jce.AES256CBC");

        config.put("aes128-ctr", "SSHServer.jce.AES128CTR");
        config.put("aes192-ctr", "SSHServer.jce.AES192CTR");
        config.put("aes256-ctr", "SSHServer.jce.AES256CTR");
        config.put("3des-ctr", "SSHServer.jce.TripleDESCTR");
        config.put("arcfour", "SSHServer.jce.ARCFOUR");
        config.put("arcfour128", "SSHServer.jce.ARCFOUR128");
        config.put("arcfour256", "SSHServer.jce.ARCFOUR256");

        config.put("userauth.none", "SSHServer.UserAuthNone");
        config.put("userauthlinux.none", "SSHServer.UserAuthNonelinux");
        config.put("userauth.password", "SSHServer.UserAuthPassword");
        config.put("userauth.keyboard-interactive", "SSHServer.UserAuthKeyboardInteractive");
        config.put("userauth.publickey", "SSHServer.UserAuthPublicKey");
        config.put("userauth.gssapi-with-mic", "SSHServer.UserAuthGSSAPIWithMIC");
        config.put("gssapi-with-mic.krb5", "SSHServer.jgss.GSSContextKrb5");

        config.put("zlib", "SSHServer.jcraft.Compression");
        config.put("zlib@openssh.com", "SSHServer.jcraft.Compression");

        config.put("pbkdf", "SSHServer.jce.PBKDF");

        config.put("StrictHostKeyChecking", "ask");
        config.put("HashKnownHosts", "no");
        
        config.put("PreferredAuthentications", "none");
//        config.put("PreferredAuthentications", "password");

        config.put("CheckCiphers", "aes256-ctr,aes192-ctr,aes128-ctr,aes256-cbc,aes192-cbc,aes128-cbc,3des-ctr,arcfour,arcfour128,arcfour256");
        config.put("CheckKexes", "diffie-hellman-group14-sha1,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521");
        config.put("CheckSignatures", "ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521");

        config.put("MaxAuthTries", "6");
        config.put("ClearAllForwardings", "no");
    }

    private java.util.Vector sessionPool = new java.util.Vector();

    /**
     * Sets the <code>identityRepository</code>, which will be referred in the
     * public key authentication.
     *
     * @param identityRepository if <code>null</code> is given, the default
     * repository, which usually refers to ~/.ssh/, will be used.
     *
     * @see #getIdentityRepository()
     */
// 
//
//    protected void addSession(Session session) {
//        synchronized (sessionPool) {
//            sessionPool.addElement(session);
//        }
//    }
//
//    protected boolean removeSession(Session session) {
//        synchronized (sessionPool) {
//            return sessionPool.remove(session);
//        }
//    }
    public static String getConfig(String key) {
        synchronized (config) {
            return (String) (config.get(key));
        }
    }

    /**
     * Sets or Overrides the configuration.
     *
     * @param newconf configurations
     */
    public static void setConfig(java.util.Hashtable newconf) {
        synchronized (config) {
            for (java.util.Enumeration e = newconf.keys(); e.hasMoreElements();) {
                String key = (String) (e.nextElement());
                config.put(key, (String) (newconf.get(key)));
            }
        }
    }

    /**
     * Sets or Overrides the configuration.
     *
     * @param key key for the configuration
     * @param value value for the configuration
     */
    public static void setConfig(String key, String value) {
        config.put(key, value);
    }
    
    
    private static ConfigRepository configRepository = null;
    public static ConfigRepository getConfigRepository() {
        return Configure.configRepository;
    }
}
