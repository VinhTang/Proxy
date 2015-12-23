package SSHServer;

import proxy.Tools;

class UserAuthNone extends UserAuth {

    private static final int SSH_MSG_SERVICE_REQUEST = 5;
    private static final int SSH_MSG_SERVICE_ACCEPT = 6;

    private String methods = null;

    public boolean start(sshServer session) throws Exception {
        super.start(session);
        try {

            //--------receive SSH_MSG_SERVICE_REQUEST (5)---------------------------
            // byte      SSH_MSG_SERVICE_REQUEST(5)        
            buf.reset();
            buf = session.read(buf);
            int command = buf.getCommand();
            if (command != SSH_MSG_SERVICE_REQUEST) {
                proxy.Logs.Println(proxy.Logger.INFO, "Expect signal SSH_MSG_SERVICE_REQUEST fail ! Disconnect",true);
                session.disconnectpacket("Expect signal SSH_MSG_USERAUTH_REQUEST fail ! Disconnect");
                session.disconnect();
            }
            proxy.Logs.Println(proxy.Logger.INFO, "SSH_MSG_SERVICE_REQUEST received",true);
        //----------------------------------------------------------------------

            //--------send SSH_MSG_SERVICE_ACCEPT (6)-------------------------------
            // byte      SSH_MSG_SERVICE_ACCEPT(6)
            // string    "ssh-userauth"
            buf.reset();
            packet.reset();
            buf.putByte((byte) SSH_MSG_SERVICE_ACCEPT);
            buf.putString(Tools.str2byte("ssh-userauth"));
            session.write(packet);
        //----------------------------------------------------------------------

            //--------receive SSH_MSG_USERAUTH_REQUEST (50)---------------------
            // byte      SSH_MSG_USERAUTH_REQUEST(50)
            // string    user name
            // string    service name ("ssh-connection")
            // string    "none"
            buf.reset();
            buf = session.read(buf);
            command = buf.getCommand();
            if (command != SSH_MSG_USERAUTH_REQUEST) {
                proxy.Logs.Println(proxy.Logger.INFO, "Expect signal SSH_MSG_USERAUTH_REQUEST fail ! Disconnect",true);
                session.disconnectpacket("Expect signal SSH_MSG_USERAUTH_REQUEST fail ! Disconnect");
                session.disconnect();
            }
            buf.getInt();
            buf.getByte();
            buf.getByte();
            byte[] username = buf.getString();
            byte[] servicename = buf.getString();
            byte[] methodsname = buf.getString();

            //------------------------------------------------------------------
            //--------send Auth Method of sshServer (50)------------------------
            buf.reset();
            packet.reset();
//            methods = session.GetPreferredAuthentications();
//            buf.putByte((byte) SSH_MSG_USERAUTH_FAILURE);
//            buf.putString(Tools.str2byte(methods));
//            buf.putByte((byte) 0);
//            session.write(packet);

            buf.putByte((byte) SSH_MSG_USERAUTH_SUCCESS);
            session.write(packet);
            
            //------------------------------------------------------------------

            return true;
        } catch (Exception e) {
            proxy.Logs.Println(proxy.Logger.ERROR, "USERAUTH fail",true);
            return false;

        }
    }

    public String getMethods() {
        return methods;
    }
}
