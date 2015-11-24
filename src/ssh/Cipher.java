package ssh;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
public interface Cipher {

    static int ENCRYPT_MODE = 0;
    static int DECRYPT_MODE = 1;

    int getIVSize();

    int getBlockSize();

    void init(int mode, byte[] key, byte[] iv) throws Exception;

    void update(byte[] foo, int s1, int len, byte[] bar, int s2) throws Exception;

    boolean isCBC();
}
