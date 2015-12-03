/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package proxy;

import SSHServer.Buffer;
import SSHServer.Packet;
import SSHServer.sshLinux;
import SSHServer.sshServer;
import java.io.IOException;

public class ClienttoServer extends Thread {

    sshLinux LinuxSide;
    sshServer ServerSide;
    Proxy proxy;

    Buffer buf;
    Packet packet;

    public ClienttoServer(Proxy _proxy, sshServer server, sshLinux linux) {
        proxy = _proxy;
        LinuxSide = linux;
        ServerSide = server;
        buf = new Buffer();
        packet = new Packet(buf);
    }

    @Override
    public void run() {
        int dlen = 0;
        boolean Active = true;
        while (Active == true) {
            try {
                buf.reset();
                dlen = CheckClientData();
                
                if (dlen < 0) {
                    Active = false;
                }
                if (dlen > 0) {
                    SendToServer(buf, dlen);
                }
            } catch (Exception ex) {
                Active = false;
            }

        }
        proxy.Close();
    }

    public int CheckClientData() throws Exception {

        //	The client side is not opened.
        if (ServerSide == null) {
            return -1;
        }
        int dlen = 0;
        try {
            buf.reset();
            buf = ServerSide.read(buf);
            dlen = buf.getLength();
        } catch (IOException e) {
            return -1;
        }
        return dlen;

    }

    private void SendToServer(Buffer buff, int dlen) throws Exception {
        if (LinuxSide == null) {
            return;
        }
        if (dlen <= 0 || dlen > buff.getLength()) {
            return;
        }
        buf.reset();
        buf = configbuffer(buff);

        LinuxSide.write(packet);

    }

    private Buffer configbuffer(Buffer buff) {
        int lenght = buff.getInt();
        int pad = buff.getByte();
        buf.reset();
        packet.reset();
        System.arraycopy(buff.buffer, 5, buf.buffer, 5, lenght - pad - 1);
        buf.skip(lenght - pad - 1);
        return buf;
    }
}
