package SSHServer;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */


public interface KeyPairGenDSA {

    void init(int key_size) throws Exception;

    byte[] getX();

    byte[] getY();

    byte[] getP();

    byte[] getQ();

    byte[] getG();
}
