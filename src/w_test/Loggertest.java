/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package w_test;

import SSHClient.*;
import java.awt.*;
import javax.swing.*;

public class Loggertest {

    public static void main(String[] arg) {

        try {
            JSch.setLogger(new MyLogger());
            JSch jsch = new JSch();

            String host = null;

            String user = "vinh";
            host = "192.168.10.111";

            Session session = jsch.getSession(user, host, 22);
            session.setPassword("123");
            // username and password will be given via UserInfo interface.
//            UserInfo ui = new MyUserInfo();
//            session.setUserInfo(ui);

            session.connect();

            Channel channel = session.openChannel("shell");
            channel.setInputStream(System.in);
            channel.setOutputStream(System.out);            
            
            channel.connect();
            
        } catch (Exception e) {
            System.out.println(e);
        }
    }

    public static class MyLogger implements SSHClient.Logger {

        static java.util.Hashtable name = new java.util.Hashtable();

        static {
            name.put(new Integer(DEBUG), "DEBUG: ");
            name.put(new Integer(INFO), "INFO: ");
            name.put(new Integer(WARN), "WARN: ");
            name.put(new Integer(ERROR), "ERROR: ");
            name.put(new Integer(FATAL), "FATAL: ");
        }

        public boolean isEnabled(int level) {
            return true;
        }

        public void log(int level, String message) {
            System.err.print(name.get(new Integer(level)));
            System.err.println(message);
        }
    }

}
