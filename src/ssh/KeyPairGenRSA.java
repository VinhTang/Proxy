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
public interface KeyPairGenRSA extends java.io.Serializable {


    void init(int key_size) throws Exception;

    byte[] getD();

    byte[] getE();

    byte[] getN();

    byte[] getC();

    byte[] getEP();

    byte[] getEQ();

    byte[] getP();

    byte[] getQ();
}
