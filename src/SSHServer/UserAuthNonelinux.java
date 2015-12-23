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

import proxy.Logs;

class UserAuthNonelinux extends UserAuthlinux {

    private static final int SSH_MSG_SERVICE_ACCEPT = 6;
    private String methods = null;

    public boolean start(sshLinux session) throws Exception {
        super.start(session);

        // send
        // byte      SSH_MSG_SERVICE_REQUEST(5)
        // string    service name "ssh-userauth"
        packet.reset();
        buf.putByte((byte) sshLinux.SSH_MSG_SERVICE_REQUEST);
        buf.putString(proxy.Tools.str2byte("ssh-userauth"));
        session.write(packet);

        if (Logs.getLogger().isEnabled(proxy.Logger.INFO)) {
            Logs.Println(proxy.Logger.INFO,
                    "SSH_MSG_SERVICE_REQUEST sent",true);
        }

        // receive
        // byte      SSH_MSG_SERVICE_ACCEPT(6)
        // string    service name
        buf = session.read(buf);
        int command = buf.getCommand();

        boolean result = (command == SSH_MSG_SERVICE_ACCEPT);

        if (Logs.getLogger().isEnabled(proxy.Logger.INFO)) {
            Logs.Println(proxy.Logger.INFO,
                    "SSH_MSG_SERVICE_ACCEPT received",true);
        }
        if (!result) {
            return false;
        }

        byte[] _username = null;
        _username = proxy.Tools.str2byte(username);

        // send
        // byte      SSH_MSG_USERAUTH_REQUEST(50)
        // string    user name
        // string    service name ("ssh-connection")
        // string    "none"
        packet.reset();
        buf.putByte((byte) SSH_MSG_USERAUTH_REQUEST);
        buf.putString(_username);
        buf.putString(proxy.Tools.str2byte("ssh-connection"));
        buf.putString(proxy.Tools.str2byte("none"));
        session.write(packet);

        loop:
        while (true) {
            buf = session.read(buf);
            command = buf.getCommand() & 0xff;

            if (command == SSH_MSG_USERAUTH_SUCCESS) {
                return true;
            }
            if (command == SSH_MSG_USERAUTH_FAILURE) {
                buf.getInt();
                buf.getByte();
                buf.getByte();
                byte[] foo = buf.getString();
                int partial_success = buf.getByte();
                methods = proxy.Tools.byte2str(foo);

                break;
            } else {
//      System.err.println("USERAUTH fail ("+command+")");
                throw new ProxyException("USERAUTH fail (" + command + ")");
            }
        }
        //throw new ProxyException("USERAUTH fail");
        return false;
    }

    String getMethods() {
        return methods;
    }
}
