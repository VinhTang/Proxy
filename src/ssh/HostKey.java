/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package ssh;

public class HostKey {

    private static final byte[][] names = {
        proxy.Tools.str2byte("ssh-dss"),
        proxy.Tools.str2byte("ssh-rsa"),
        proxy.Tools.str2byte("ecdsa-sha2-nistp256"),
        proxy.Tools.str2byte("ecdsa-sha2-nistp384"),
        proxy.Tools.str2byte("ecdsa-sha2-nistp521")
    };

    protected static final int GUESS = 0;
    public static final int SSHDSS = 1;
    public static final int SSHRSA = 2;
    public static final int ECDSA256 = 3;
    public static final int ECDSA384 = 4;
    public static final int ECDSA521 = 5;
    static final int UNKNOWN = 6;

    protected String marker;
    protected String host;
    protected int type;
    protected byte[] key;
    protected String comment;

    public HostKey(String host, byte[] key) throws ProxyException {
        this(host, GUESS, key);
    }

    public HostKey(String host, int type, byte[] key) throws ProxyException {
        this(host, type, key, null);
    }

    public HostKey(String host, int type, byte[] key, String comment) throws ProxyException {
        this("", host, type, key, comment);
    }

    public HostKey(String marker, String host, int type, byte[] key, String comment) throws ProxyException {
        this.marker = marker;
        this.host = host;
        if (type == GUESS) {
            if (key[8] == 'd') {
                this.type = SSHDSS;
            } else if (key[8] == 'r') {
                this.type = SSHRSA;
            } else if (key[8] == 'a' && key[20] == '2') {
                this.type = ECDSA256;
            } else if (key[8] == 'a' && key[20] == '3') {
                this.type = ECDSA384;
            } else if (key[8] == 'a' && key[20] == '5') {
                this.type = ECDSA521;
            } else {
                throw new ProxyException("invalid key type");
            }
        } else {
            this.type = type;
        }
        this.key = key;
        this.comment = comment;
    }

    public String getHost() {
        return host;
    }

    public String getType() {
        if (type == SSHDSS
                || type == SSHRSA
                || type == ECDSA256
                || type == ECDSA384
                || type == ECDSA521) {
            return proxy.Tools.byte2str(names[type - 1]);
        }
        return "UNKNOWN";
    }

    protected static int name2type(String name) {
        for (int i = 0; i < names.length; i++) {
            if (proxy.Tools.byte2str(names[i]).equals(name)) {
                return i + 1;
            }
        }
        return UNKNOWN;
    }

    public String getKey() {
        return proxy.Tools.byte2str(proxy.Tools.toBase64(key, 0, key.length));
    }

    public String getFingerPrint(Configure jsch) {
        HASH hash = null;
        try {
            Class c = Class.forName(jsch.getConfig("md5"));
            hash = (HASH) (c.newInstance());
        } catch (Exception e) {
            System.err.println("getFingerPrint: " + e);
        }
        return proxy.Tools.getFingerPrint(hash, key);
    }

    public String getComment() {
        return comment;
    }

    public String getMarker() {
        return marker;
    }

    boolean isMatched(String _host) {
        return isIncluded(_host);
    }

    private boolean isIncluded(String _host) {
        int i = 0;
        String hosts = this.host;
        int hostslen = hosts.length();
        int hostlen = _host.length();
        int j;
        while (i < hostslen) {
            j = hosts.indexOf(',', i);
            if (j == -1) {
                if (hostlen != hostslen - i) {
                    return false;
                }
                return hosts.regionMatches(true, i, _host, 0, hostlen);
            }
            if (hostlen == (j - i)) {
                if (hosts.regionMatches(true, i, _host, 0, hostlen)) {
                    return true;
                }
            }
            i = j + 1;
        }
        return false;
    }
}
