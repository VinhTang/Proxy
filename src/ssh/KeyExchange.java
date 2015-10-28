/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package ssh;

import proxy.Tools;

public abstract class KeyExchange {

    static final int PROPOSAL_KEX_ALGS = 0;
    static final int PROPOSAL_SERVER_HOST_KEY_ALGS = 1;
    static final int PROPOSAL_ENC_ALGS_CTOS = 2;
    static final int PROPOSAL_ENC_ALGS_STOC = 3;
    static final int PROPOSAL_MAC_ALGS_CTOS = 4;
    static final int PROPOSAL_MAC_ALGS_STOC = 5;
    static final int PROPOSAL_COMP_ALGS_CTOS = 6;
    static final int PROPOSAL_COMP_ALGS_STOC = 7;
    static final int PROPOSAL_LANG_CTOS = 8;
    static final int PROPOSAL_LANG_STOC = 9;
    static final int PROPOSAL_MAX = 10;

  //static String kex_algs="diffie-hellman-group-exchange-sha1"+
    //                       ",diffie-hellman-group1-sha1";
//static String kex="diffie-hellman-group-exchange-sha1";
    static String kex = "diffie-hellman-group1-sha1";
    static String server_host_key = "ssh-rsa,ssh-dss";
    static String enc_c2s = "blowfish-cbc";
    static String enc_s2c = "blowfish-cbc";
    static String mac_c2s = "hmac-md5";     // hmac-md5,hmac-sha1,hmac-ripemd160,
    // hmac-sha1-96,hmac-md5-96
    static String mac_s2c = "hmac-md5";
//static String comp_c2s="none";        // zlib
//static String comp_s2c="none";
    static String lang_c2s = "";
    static String lang_s2c = "";

    public static final int STATE_END = 0;

//  protected HASH sha=null;
    protected byte[] K = null;
    protected byte[] H = null;
    protected byte[] K_S = null;

    public abstract void init(
            byte[] V_S, byte[] V_C, byte[] I_S, byte[] I_C) throws Exception;

    public abstract String getKeyType();

    public abstract int getState();

    /*
     void dump(byte[] foo){
     for(int i=0; i<foo.length; i++){
     if((foo[i]&0xf0)==0)System.err.print("0");
     System.err.print(Integer.toHexString(foo[i]&0xff));
     if(i%16==15){System.err.println(""); continue;}
     if(i%2==1)System.err.print(" ");
     }
     } 
     */
    protected static String[] guess(byte[] I_S, byte[] I_C) {
        String[] guess = new String[PROPOSAL_MAX];
        Buffer sb = new Buffer(I_S);
        sb.setOffSet(17);
        Buffer cb = new Buffer(I_C);
        cb.setOffSet(17);

        for (int i = 0; i < PROPOSAL_MAX; i++) {
            byte[] sp = sb.getString();  // server proposal
            byte[] cp = cb.getString();  // client proposal
            int j = 0;
            int k = 0;

            loop:
            while (j < cp.length) {
                while (j < cp.length && cp[j] != ',') {
                    j++;
                }
                if (k == j) {
                    return null;
                }
                String algorithm = proxy.Tools.byte2str(cp, k, j - k);
                int l = 0;
                int m = 0;
                while (l < sp.length) {
                    while (l < sp.length && sp[l] != ',') {
                        l++;
                    }
                    if (m == l) {
                        return null;
                    }
                    if (algorithm.equals(proxy.Tools.byte2str(sp, m, l - m))) {
                        guess[i] = algorithm;
                        break loop;
                    }
                    l++;
                    m = l;
                }
                j++;
                k = j;
            }
            if (j == 0) {
                guess[i] = "";
            } else if (guess[i] == null) {
                return null;
            }
        }

//    if(JSch.getLogger().isEnabled(Logger.INFO)){
//      JSch.getLogger().log(Logger.INFO, 
//                           "kex: server->client"+
//                           " "+guess[PROPOSAL_ENC_ALGS_STOC]+
//                           " "+guess[PROPOSAL_MAC_ALGS_STOC]+
//                           " "+guess[PROPOSAL_COMP_ALGS_STOC]);
//      JSch.getLogger().log(Logger.INFO, 
//                           "kex: client->server"+
//                           " "+guess[PROPOSAL_ENC_ALGS_CTOS]+
//                           " "+guess[PROPOSAL_MAC_ALGS_CTOS]+
//                           " "+guess[PROPOSAL_COMP_ALGS_CTOS]);
//    }
//    for(int i=0; i<PROPOSAL_MAX; i++){
//      System.err.println("guess: ["+guess[i]+"]");
//    }
        return guess;
    }

//  public String getFingerPrint(){
//    HASH hash=null;
//    try{
//      Class c=Class.forName(session.getConfig("md5"));
//      hash=(HASH)(c.newInstance());
//    }
//    catch(Exception e){ System.err.println("getFingerPrint: "+e); }
//    return Util.getFingerPrint(hash, getHostKey());
//  }
//  byte[] getK(){ return K; }
//  byte[] getH(){ return H; }
//  HASH getHash(){ return sha; }
//  byte[] getHostKey(){ return K_S; }
}
