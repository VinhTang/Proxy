package proxy;

import java.net.InetAddress;
import java.net.Socket;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
/**
 *
 * @author Milky_Way
 */
public class Logs {

    public static final String EOL = "\r\n";
    public static boolean ProxyLog, ClientLog;

    ////////////////////////////////////////////////////////////////////////////
    private static DateFormat dateFormat;
    private static Date date;

    private static final Logger DEVNULL = new Logger() {

        public boolean isEnabled(int level) {
            return false;
        }

        public void log(int level, String message) {

        }

        public void logproxy(int level, String message) {

        }

        public void logclient(int level, String message) {

        }
    };
    static Logger logger = DEVNULL;

    public static void setLogger(Logger logger) {
        if (logger == null) {
            Logs.logger = DEVNULL;

        }
        Logs.logger = logger;
    }

    public static Logger getLogger() {
        return logger;
    }

    //--------------------------------------------------------------------------
    public static class ProxyLog implements proxy.Logger {

        static java.util.Hashtable name = new java.util.Hashtable();

        static {
            name.put(DEBUG, "DEBUG: ");
            name.put(INFO, "INFO: ");
            name.put(WARN, "WARN: ");
            name.put(ERROR, "ERROR: ");
            name.put(FATAL, "FATAL: ");
        }

        public boolean isEnabled(int level) {
            return true;
        }

        public void logproxy(int level, String message) {
            dateFormat = new SimpleDateFormat("MMM dd,yyyy HH:mm:ssa");
            date = new Date();
            //            System.out.println(dateFormat.format(date));
            switch (level) {
                case Logger.INFO:
                    System.out.print("[" + dateFormat.format(date) + "]- " + name.get(new Integer(level)));
                    System.out.println(message);
                    break;
                case Logger.ERROR:
                    System.err.print("\033[1;31m[" + dateFormat.format(date) + "]-" + name.get(new Integer(level)));
                    System.err.println(message.toUpperCase());
                    break;
                case Logger.DEBUG:
                    Exception e = new Exception();
                    System.out.print("\033[0;34m[" + dateFormat.format(date) + "]-" + name.get(new Integer(level)));
                    System.out.println(message.toUpperCase() + " -BY CLASS: " + e.getStackTrace()[2].getClassName()
                            + "." + e.getStackTrace()[2].getMethodName());
                    break;
                default:
                    System.out.print("[" + dateFormat.format(date) + "]-" + name.get(new Integer(level)));
                    System.out.println(message);
                    break;
            }
        }

        public void logclient(int level, String message) {

        }
    }

//------------------------------------------------------------------------------
    public static class ClientLog implements Logger {

        static Socket ClientSock;

        public ClientLog(Socket ClientSocket) {
            ClientSock = ClientSocket;
        }

        static java.util.Hashtable name = new java.util.Hashtable();

        static {
            name.put(DEBUG, "DEBUG: ");
            name.put(INFO, "INFO: ");
            name.put(WARN, "WARN: ");
            name.put(ERROR, "ERROR: ");
            name.put(FATAL, "FATAL: ");
        }

        public boolean isEnabled(int level) {
            return true;
        }

        public void logclient(int level, String message) {
            dateFormat = new SimpleDateFormat("MMM dd,yyyy HH:mm:ssa");
            date = new Date();
            //            System.out.println(dateFormat.format(date));
            Exception e = new Exception();
            switch (level) {
                case Logger.INFO:
                    System.out.print("[" + dateFormat.format(date) + "]- " + getSocketInfo(ClientSock) + name.get(new Integer(level)));
                    System.out.println(message);
                    break;
                case Logger.ERROR:

                    System.out.print("\033[0;31m[" + dateFormat.format(date) + "]-" + name.get(new Integer(level)));
                    System.out.println(message.toUpperCase() + " -BY CLASS: " + e.getStackTrace()[2].getClassName()
                            + "." + e.getStackTrace()[2].getMethodName());
                    break;
                case Logger.DEBUG:

                    System.out.print("\033[0;34m[" + dateFormat.format(date) + "]-" + name.get(new Integer(level)));
                    System.out.println(message.toUpperCase() + " -BY CLASS: " + e.getStackTrace()[2].getClassName()
                            + "." + e.getStackTrace()[2].getMethodName());
                    break;
                default:
                    System.out.print("[" + dateFormat.format(date) + "]-" + name.get(new Integer(level)));
                    System.out.println(message);
                    break;
            }
        }

        public void logproxy(int level, String message) {
        }

    }

    ////////////////////////////////////////////////////////////////////////////
    public static void Println(int level, String txt) {
//        System.err.println("level:"+level);
        //System.err.println(new Exception().getStackTrace()[1].toString());
        if (Logs.getLogger().isEnabled(level)) {
            Logs.getLogger().logclient(level, txt);
        }
    }

    public static void PrintlnProxy(int level, String txt) {
        //        System.err.println("level:"+level);
        //System.err.println(new Exception().getStackTrace()[1].toString());
        if (Logs.getLogger().isEnabled(level)) {
            Logs.getLogger().logproxy(level, txt);
        }
    }
//    public static void Print(String txt) {
//        if (EnableLog == false) {
//            return;
//        }
//        if (txt == null) {
//            return;
//        }
//        System.out.print(txt);
//    }
    ////////////////////////////////////////////////////////////////////////////
//    public static void Error(String txt) {
//        if (EnableLog == true) {
//            Println("Error : " + txt);
//        }
//    }
//
//    public static void Error(Exception e) {
//        if (!EnableLog) {
//            return;
//        }
//        Println("ERROR : " + e.toString());
//        e.printStackTrace();
//
//    }
    ////////////////////////////////////////////////////////////////////////////

    static String getSocketInfo(Socket Sock) {
        if (Sock == null) {
            return "NA / NA:0";
        }
        String Info = "<" + IP2Str(Sock.getInetAddress()) + ":" + Sock.getPort() + ">";
        return Info;
    }

    ////////////////////////////////////////////////////////////////////////////
    public static String IP2Str(InetAddress IP) {
        if (IP == null) {
            return "NA / NA";
        }
        return "Hostname: " + IP.getHostName() + " / " + IP.getHostAddress();
    }
    ////////////////////////////////////////////////////////////////////////////

}
