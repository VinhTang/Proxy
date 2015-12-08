/* -*-mode:java; c-basic-offset:2; indent-tabs-mode:nil -*- */
/*
 Copyright (c) 2002-2015 ymnk, JCraft,Inc. All rights reserved.

 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions are met:

 1. Redistributions of source code must retain the above copyright notice,
 this list of conditions and the following disclaimer.

 2. Redistributions in binary form must reproduce the above copyright 
 notice, this list of conditions and the following disclaimer in 
 the documentation and/or other materials provided with the distribution.

 3. The names of the authors may not be used to endorse or promote products
 derived from this software without specific prior written permission.

 THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED WARRANTIES,
 INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
 FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL JCRAFT,
 INC. OR ANY CONTRIBUTORS TO THIS SOFTWARE BE LIABLE FOR ANY DIRECT, INDIRECT,
 INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
 OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
package SSHServer;

class UserAuthPasswordlinux extends UserAuthlinux {

    private final int SSH_MSG_USERAUTH_PASSWD_CHANGEREQ = 60;

    public boolean start(sshLinux session) throws Exception {
        super.start(session);
        
        byte[] password = session.passwordSSH;
        username = session.usernameSSH;
        
        
        try {

            while (true) {

                if (session.auth_failures >= session.max_auth_tries) {
                    return false;
                }
  // send
                // byte      SSH_MSG_USERAUTH_REQUEST(50)
                // string    user name
                // string    service name ("ssh-connection")
                // string    "password"
                // boolen    FALSE
                // string    plaintext password (ISO-10646 UTF-8)
                packet.reset();
                buf.putByte((byte) SSH_MSG_USERAUTH_REQUEST);
                buf.putString(proxy.Tools.str2byte(username));
                buf.putString(proxy.Tools.str2byte("ssh-connection"));
                buf.putString(proxy.Tools.str2byte("password"));
                buf.putByte((byte) 0);
                buf.putString(password);
                session.write(packet);

                loop:
                while (true) {
                    buf = session.read(buf);
                    int command = buf.getCommand() & 0xff;

                    if (command == SSH_MSG_USERAUTH_SUCCESS) {
                        return true;
                    }
                    if (command == SSH_MSG_USERAUTH_BANNER) {
                        buf.getInt();
                        buf.getByte();
                        buf.getByte();
                        byte[] _message = buf.getString();
                        byte[] lang = buf.getString();
                        String message = proxy.Tools.byte2str(_message);
                        continue loop;
                    }
                    if (command == SSH_MSG_USERAUTH_PASSWD_CHANGEREQ) {
                        buf.getInt();
                        buf.getByte();
                        buf.getByte();
                        byte[] instruction = buf.getString();
                        byte[] tag = buf.getString();
                        return false;
                    }

                    if (command == SSH_MSG_USERAUTH_FAILURE) {
                        buf.getInt();
                        buf.getByte();
                        buf.getByte();
                        byte[] foo = buf.getString();
                        int partial_success = buf.getByte();
	  //System.err.println(new String(foo)+
                        //		 " partial_success:"+(partial_success!=0));
                        if (partial_success != 0) {
                            throw new ProxyPartialAuthException(proxy.Tools.byte2str(foo));
                        }
                        session.auth_failures++;
                        break;
                    } else {
                        //System.err.println("USERAUTH fail ("+buf.getCommand()+")");
//	  throw new JSchException("USERAUTH fail ("+buf.getCommand()+")");
                        return false;
                    }
                }

                if (password != null) {
                    proxy.Tools.bzero(password);
                    password = null;
                }

            }

        } finally {
            if (password != null) {
                proxy.Tools.bzero(password);
                password = null;
            }
        }
    }
}
