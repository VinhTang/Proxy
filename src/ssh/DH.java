/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package ssh;

public interface DH {

    void init() throws Exception;

    void setP(byte[] p);

    void setG(byte[] g);

    byte[] getE() throws Exception;

    void setF(byte[] f);

    byte[] getK() throws Exception;
}
