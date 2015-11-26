package SSHServer;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
public interface HASH {

    void init() throws Exception;

    int getBlockSize();

    void update(byte[] foo, int start, int len) throws Exception;

    byte[] digest() throws Exception;
}
