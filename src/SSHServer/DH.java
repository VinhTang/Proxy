package SSHServer;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
public interface DH {

    void init() throws Exception;

    void setP(byte[] p);

    void setG(byte[] g);

    byte[] getE() throws Exception;

    void setF(byte[] f);

    byte[] getK() throws Exception;

  // checkRange() will check if e and f are in [1,p-1]
    // as defined at https://tools.ietf.org/html/rfc4253#section-8
    void checkRange() throws Exception;

}
