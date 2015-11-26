package SSHServer;
/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 *
 * @author Milky_Way
 */

public interface SignatureDSA extends Signature {

    void setPubKey(byte[] y, byte[] p, byte[] q, byte[] g) throws Exception;

    void setPrvKey(byte[] x, byte[] p, byte[] q, byte[] g) throws Exception;
}
