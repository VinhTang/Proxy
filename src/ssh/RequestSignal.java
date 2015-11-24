/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package ssh;

public class RequestSignal extends Request {

    private String signal = "KILL";

    public void setSignal(String foo) {
        signal = foo;
    }

    public void request(SessionSSH session, Channel channel) throws Exception {
        super.request(session, channel);

        Buffer buf = new Buffer();
        Packet packet = new Packet(buf);

        packet.reset();
        buf.putByte((byte) SessionSSH.SSH_MSG_CHANNEL_REQUEST);
        buf.putInt(channel.getRecipient());
        buf.putString(proxy.Tools.str2byte("signal"));
        buf.putByte((byte) (waitForReply() ? 1 : 0));
        buf.putString(proxy.Tools.str2byte(signal));
        write(packet);
    }
}
