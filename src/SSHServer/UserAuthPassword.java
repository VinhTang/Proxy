package SSHServer;

import java.io.IOException;
import java.util.Arrays;
import proxy.Tools;

class UserAuthPassword extends UserAuth {

    private final int SSH_MSG_USERAUTH_PASSWD_CHANGEREQ = 60;

    public boolean start(sshServer session) throws Exception {
        super.start(session);
        try {
            //----------------------------------------------
            byte[] methodname = Tools.str2byte(session.GetPreferredAuthentications());
            String username = session.username;
            byte[] password = session.password;
            byte[] Spassword = session.Spassword;
            byte[] H_pass;
            int command;
            HASH sha = null;
            //----------------------------------------------
            if (session.auth_failures == session.max_auth_tries) {
                
                return false;
            }
            try {
                Class c = Class.forName(session.getConfig("sha-1"));
                sha = (HASH) (c.newInstance());
                sha.init();
            } catch (Exception ee) {
                
            }

            if (session.firstcheck == true) {
                session.firstcheck = false;
                sha.update(password, 0, password.length);
                H_pass = sha.digest();
                buf.reset();
                packet.reset();
                if (Arrays.equals(Spassword, H_pass) == true) {
                    buf.putByte((byte) SSH_MSG_USERAUTH_SUCCESS);
                    session.write(packet);
                    return true;
                } else {
                    buf.putByte((byte) SSH_MSG_USERAUTH_FAILURE);
                    buf.putString(methodname);
                    buf.putByte((byte) 0);
                    session.write(packet);
                    return false;
                }
            }

            // send
            // byte      SSH_MSG_USERAUTH_REQUEST(50)
            // string    user name
            // string    service name ("ssh-connection")
            // string    "password"
            // boolen    FALSE
            // string    plaintext password (ISO-10646 UTF-8)
            buf.reset();

            buf = session.read(buf);
            command = buf.getCommand();

            buf.getInt();
            buf.getByte();
            int i = buf.getByte();

            username = proxy.Tools.byte2str(buf.getString());
            byte[] servicename = buf.getString();
            byte[] _methodname = buf.getString();
            int bool = buf.getByte();
            password = buf.getString();
            //System.err.println(proxy.Tools.byte2str(password));

            //----------------- hash password to check--------------------------
            sha.update(password, 0, password.length);
            H_pass = sha.digest();
            //------------------------------------------------------------------

            buf.reset();

            packet.reset();
            if (Arrays.equals(Spassword, H_pass) == true) {

                buf.putByte((byte) SSH_MSG_USERAUTH_SUCCESS);
                session.write(packet);
                return true;
            } else {
                buf.putByte((byte) SSH_MSG_USERAUTH_FAILURE);

                buf.putString(methodname);
                buf.putByte((byte) 0);
                session.write(packet);

                return false;
            }
        } catch (IOException ee) {

            session.auth_failures = 5;
            return false;
        }

    }

}
