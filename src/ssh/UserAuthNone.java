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
package ssh;

import proxy.Tools;

class UserAuthNone extends UserAuth {

    private static final int SSH_MSG_SERVICE_REQUEST = 5;
    private static final int SSH_MSG_SERVICE_ACCEPT = 6;

    private String methods = null;

    public boolean start(SessionSSH session) throws Exception {
        super.start(session);
        try {

            //--------receive SSH_MSG_SERVICE_REQUEST (5)---------------------------
            // byte      SSH_MSG_SERVICE_REQUEST(5)        
            buf.reset();
            buf = session.read(buf);
            int command = buf.getCommand();
            if (command != SSH_MSG_SERVICE_REQUEST) {
                proxy.Logs.Println(proxy.Logger.INFO, "Expect signal SSH_MSG_SERVICE_REQUEST fail ! Disconnect");
                session.disconnectpacket("Expect signal SSH_MSG_USERAUTH_REQUEST fail ! Disconnect");
                session.disconnect();
            }
            proxy.Logs.Println(proxy.Logger.INFO, "SSH_MSG_SERVICE_REQUEST received");
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
                proxy.Logs.Println(proxy.Logger.INFO, "Expect signal SSH_MSG_USERAUTH_REQUEST fail ! Disconnect");
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
            //--------send Auth Method of Server (50)---------------------------
            buf.reset();
            packet.reset();
            methods = session.GetPreferredAuthentications();
            buf.putByte((byte) SSH_MSG_USERAUTH_FAILURE);
            buf.putString(Tools.str2byte(methods));
            buf.putInt(0);

            session.write(packet);
            //------------------------------------------------------------------

            return true;
        } catch (Exception e) {
            proxy.Logs.Println(proxy.Logger.ERROR, "USERAUTH fail");
            return false;

        }
    }

    public String getMethods() {
        return methods;
    }
}
