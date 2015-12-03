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
import java.io.InterruptedIOException;

public class ServertoLinux extends Thread {

    sshLinux LinuxSide;
    sshServer ServerSide;
    Proxy proxy;

    Buffer buf;
    Packet packet;

    ServertoLinux(Proxy _proxy, sshServer server, sshLinux linux) {
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
                dlen = CheckLinuxData();
//
                if (dlen < 0) {
                    Active = false;
                }
                if (dlen > 0) {
                    SendToClient(buf, dlen);
                }
            } catch (Exception ex) {
                Active = false;
            }
        }
        proxy.Close();
    }

    public int CheckLinuxData() throws Exception {

        //	The client side is not opened.
        if (LinuxSide == null) {
            return -1;
        }
        int dlen = 0;
        buf.reset();
        try {
            buf.reset();
            buf = LinuxSide.read(buf);
            dlen = buf.getLength();
        } catch (IOException e) {

            return -1;
        }

        return dlen;

    }

    public void SendToClient(Buffer Buf, int Len) throws Exception {
        if (ServerSide == null) {
            return;
        }
        if (Len <= 0 || Len > Buf.getLength()) {
            return;
        }
        buf.reset();
        buf = configbuffer(Buf);
        ServerSide.write(packet);

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
