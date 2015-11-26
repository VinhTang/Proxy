package SSHServer;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.UnknownHostException;

/**
 *
 * @author Milky_Way
 */
public interface SignatureRSA extends Signature {

    void setPubKey(byte[] e, byte[] n) throws Exception;

    void setPrvKey(byte[] d, byte[] n) throws Exception;
}
