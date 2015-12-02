/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package SSHServer;

class RequestShell extends Request {

    public void request(sshServer session, Channel channel) throws Exception {
        super.request(session, channel);

        Buffer buf = new Buffer();
        Packet packet = new Packet(buf);

    // send
        // byte     SSH_MSG_CHANNEL_REQUEST(98)
        // uint32 recipient channel
        // string request type       // "shell"
        // boolean want reply        // 0
        packet.reset();
        buf.putByte((byte) sshServer.SSH_MSG_CHANNEL_REQUEST);
        buf.putInt(channel.getRecipient());
        buf.putString(proxy.Tools.str2byte("shell"));
        buf.putByte((byte) (waitForReply() ? 1 : 0));
        write(packet);
    }
}
