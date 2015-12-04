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
import java.awt.event.KeyEvent;
import java.io.IOException;
import java.util.LinkedList;
import java.util.Queue;

public class ClienttoServer extends Thread {

    sshLinux LinuxSide;
    sshServer ServerSide;
    Proxy _proxy;

    Buffer buf;
    Packet packet;

    Queue<Byte> queue;

    public ClienttoServer(Proxy proxy, sshServer server, sshLinux linux) {
        _proxy = proxy;
        LinuxSide = linux;
        ServerSide = server;
        buf = new Buffer();
        packet = new Packet(buf);
        //queue = new LinkedList<Byte>();
    }

    @Override
    public void run() {
        int dlen = 0;
        boolean Active = true;
        Buffer _buflog = new Buffer(1024); // manual configure
        while (Active == true) {
            try {
                //============================
                buf.reset();
                dlen = CheckClientData();
                //============================
                if (buf.getCommand() == SSH_MSG_CHANNEL_DATA) {
                    buf.s = 10;
                    int lendata = buf.getInt();
                    byte[] b = new byte[lendata];
                    System.arraycopy(buf.buffer, 14, b, 0, lendata);

                    if (lendata == 1) {
                        switch (b[0]) {
                            case 13: // cariage return
                                byte[] foo = new byte[_buflog.index];
                                byte temp;
                                int j = 0;
                                for (int i = 0; i < _buflog.index; i++) {
                                    temp = _buflog._getByte();
                                    if (temp >= 32 && temp != 127) {
                                        foo[j++] = temp;
                                    }
                                }
                                _buflog.reset();
                                System.arraycopy(foo, 0, foo, 0, j);
                                Logs.Println(proxy.Logger.INFO, Tools.byte2str(foo));
                                break;

                            case 127:  // del
                                if (_buflog.s != 0) {
                                    _buflog.skip(-1);
                                }
                                break;

                            default:
                                _buflog.putByte(b[0]);
                                break;

                        }

                    }
                    if (lendata > 1) {
                        System.err.println(Tools.byte2str(b));
                        System.err.println(Tools.byte2hexstr(b));
                        for (int i = 0; i < lendata; i++) {
                            _buflog.putByte(b[i]);
                        }
                    }
                }
                //============================
                buf.s = 0;
                if (dlen < 0) {
                    Active = false;
                }
                if (dlen > 0) {
                    SendToServer(buf, dlen);
                }
                //============================
            } catch (Exception ex) {
                Active = false;
            }

        }

        _proxy.Close();
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
    int SSH_MSG_CHANNEL_DATA = 94;

    private Buffer configbuffer(Buffer buff) {
        int lenght = buff.getInt();
        int pad = buff.getByte();
//      byte      SSH_MSG_CHANNEL_DATA  (5)
//      uint32    recipient channel     (4)
//      string    data    ( (uint32)  lenght; data )

        buf.reset();
        packet.reset();
        System.arraycopy(buff.buffer, 5, buf.buffer, 5, lenght - pad - 1);

        buf.skip(lenght - pad - 1);
        return buf;
    }
}
