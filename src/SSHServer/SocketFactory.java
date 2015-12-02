/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package SSHServer;
import java.net.*;
import java.io.*;

public interface SocketFactory{
  public Socket createSocket(String host, int port)throws IOException,
							  UnknownHostException;
  public InputStream getInputStream(Socket socket)throws IOException;
  public OutputStream getOutputStream(Socket socket)throws IOException;
}