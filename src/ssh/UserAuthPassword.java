package ssh;

import java.util.Arrays;
import proxy.Tools;

class UserAuthPassword extends UserAuth {

    private final int SSH_MSG_USERAUTH_PASSWD_CHANGEREQ = 60;

    public boolean start(SessionSSH session) throws Exception {
        super.start(session);
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
            proxy.Logs.Println(proxy.Logger.INFO, "Too many times authen for user " + username);
            session.disconnectpacket("Too many times authen for user " + username);
            return false;
        }
        try {
            Class c = Class.forName(session.getConfig("sha-1"));
            sha = (HASH) (c.newInstance());
            sha.init();
        } catch (Exception ee) {
            proxy.Logs.Println(proxy.Logger.ERROR, ee.toString());
        }

        try {
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
                    buf.putInt(0);
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
            buf.getByte();
            username = proxy.Tools.byte2str(buf.getString());
            byte[] servicename = buf.getString();
            byte[] _methodname = buf.getString();
            int bool = buf.getByte();
            password = buf.getString();
            //System.err.println(proxy.Tools.byte2str(password));

            //----------------- hash password to check--------------------------
            sha.update(password, 0, password.length);
            H_pass = sha.digest();

            buf.reset();
            packet.reset();
            if (Arrays.equals(Spassword, H_pass) == true && command == SSH_MSG_USERAUTH_REQUEST) {
                buf.putByte((byte) SSH_MSG_USERAUTH_SUCCESS);
                session.write(packet);
                return true;
            } else {
                buf.putByte((byte) SSH_MSG_USERAUTH_FAILURE);
                buf.putString(methodname);
                buf.putInt(0);
                session.write(packet);
                buf = session.read(buf);

                return false;
            }
        } catch (Exception e) {
            session.auth_failures = 5;
            return false;
        }
    }

}
