package proxy;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.Socket;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
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

    ////////////////////////////////////////////////////////////////////////////
    //--------------------------------------------------------------------------
//    static Logger logger = DEVNULL;
    static Logger logger;

    public static void setLogger(Logger logger) {

//        if (logger == null) {
//            Logs.logger = DEVNULL;
//        }
        Logs.logger = logger;
    }

    public static Logger getLogger() {

        return logger;
    }

    //--------------------------------------------------------------------------
    ////////////////////////////////////////////////////////////////////////////
//    private static final Logger DEVNULL = new Logger() {
//
//        public boolean isEnabled(int level) {
//            return false;
//        }
//
//        public void setUsername(String Str) {
//        }
//
//        public void logproxy(int level, String message) {
//
//        }
//
//        public void logclient(int level, String message) {
//
//        }
//
//    };
    ////////////////////////////////////////////////////////////////////////////
    //--------------------------------------------------------------------------
    public static class ProxyLog implements proxy.Logger {

        static java.util.Hashtable name = new java.util.Hashtable();
        static File AccessLog = null;
        static File Log = null;

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

        //bool = true Log ; =false AccessLogs
        public void logproxy(int level, String txt, boolean bool) {

            dateFormat = new SimpleDateFormat("MMM dd,yyyy HH:mm:ssa");
            date = new Date();
            String message = "";
            if (bool == true) {
                switch (level) {
                    case Logger.INFO:
                        message = "[" + dateFormat.format(date) + "]- " + name.get(new Integer(level)) + txt;
                        saveLog(message, true);
                        System.out.println(message);
                        break;
                    case Logger.ERROR:
                        message = "[" + dateFormat.format(date) + "]-" + name.get(new Integer(level)) + txt.toUpperCase();
                        saveLog(message, true);
                        System.err.print("\033[1;31m" + message + "\033[0;30m[");
                        break;
                    case Logger.DEBUG:
                        Exception e = new Exception();
                        message = "[" + dateFormat.format(date) + "]-" + name.get(new Integer(level))
                                + txt.toUpperCase() + " -BY CLASS: " + e.getStackTrace()[2].getClassName()
                                + "." + e.getStackTrace()[2].getMethodName();
                        saveLog(message, true);
                        System.out.print("\033[0;34m[" + message + "\033[0;30m[");
                        break;
                    default:
                        message = "[" + dateFormat.format(date) + "]-" + name.get(new Integer(level)) + txt;
                        saveLog(message, true);
                        System.out.println(message);
                        break;
                }
            } else {

                message = "[" + dateFormat.format(date) + "]-" + name.get(new Integer(level)) + txt;
                saveLog(message, false);
                System.out.println(message);

            }
        }

        FileWriter fileWriter;

        //flag =false logaccess; = true log active
        private void saveLog(String txt, boolean flag) {
            try {
                if (flag == true) {
                    fileWriter = new FileWriter(Log, true);
                } else {
                    fileWriter = new FileWriter(AccessLog, true);
                }
                BufferedWriter bufferedWriter = new BufferedWriter(fileWriter);
                bufferedWriter.write(txt + EOL);
                bufferedWriter.close();
            } catch (Exception e) {
            }
        }

        //----------------------------------------------------------------------
        public void setLogProxy() {
            setAccessLog();
            setLog();
        }

        //set accessLogs: log all client access to proxy or Web Server
        private void setAccessLog() {
            try {

//                String ProxyLogDir = "log\\accesslog-" + format.format(Calendar.getInstance().getTime());
                String ProxyLogDir = "proxy\\accessLog";
                AccessLog = new File(ProxyLogDir);

                if (AccessLog.exists() == false) {
                    AccessLog.getParentFile().mkdirs();
                }

            } catch (Exception e) {

            }
        }

        // Log all action when Proxy active
        private void setLog() {
            try {
                SimpleDateFormat format = new SimpleDateFormat("MMddyyyy");
                String ProxyLogDir = "proxy\\log-" + format.format(Calendar.getInstance().getTime());
                Log = new File(ProxyLogDir);

                if (Log.exists() == false) {
                    Log.getParentFile().mkdirs();
                }
            } catch (Exception e) {

            }
        }

        //----------------------------------------------------------------------
        public void logclient(int level, String message, boolean bool) {
        }

        public void setUsername(String _user) {
        }

        public void setLogUser() {
        }

    }

    ////////////////////////////////////////////////////////////////////////////
    public static class ClientLog implements proxy.Logger {

        static PrintWriter writer;
        static Socket ClientSock;
        static String username;

        static File _AccessLog = null;
        static File _Log = null;

        public ClientLog(Socket ClientSocket) {
            ClientSock = ClientSocket;
        }

        public void setUsername(String _user) {
            username = _user;
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

        public void logclient(int level, String txt, boolean bool) {
            dateFormat = new SimpleDateFormat("MMM dd,yyyy HH:mm:ssa");
            date = new Date();
            String message = "";

            //            System.out.println(dateFormat.format(date));
            Exception e = new Exception();
            if (bool == true) {

                switch (level) {
                    case Logger.INFO:
                        message = "[" + dateFormat.format(date) + "]- " + username + "-" + getSocketInfo(ClientSock) + name.get(new Integer(level)) + txt;
                        saveLogs(message, true);
                        System.out.println(message);
                        break;

                    case Logger.ERROR:
                        message = "[" + dateFormat.format(date) + "]- " + username + "-" + getSocketInfo(ClientSock) + name.get(new Integer(level)) + txt
                                + message.toUpperCase() + " -BY CLASS: " + e.getStackTrace()[2].getClassName()
                                + "." + e.getStackTrace()[2].getMethodName();
                        saveLogs(message, true);
                        System.err.println("\033[0;31m[" + message + "\033[0;30m");
                        break;
                    case Logger.DEBUG:
                        message = "033[0;34m[ " + dateFormat.format(date) + "]- " + username + "-" + name.get(new Integer(level)) + txt;
                        saveLogs(message, true);
                        System.out.print("\033[0;34m[" + dateFormat.format(date) + "]-" + name.get(new Integer(level)));
                        System.out.println();
                        System.out.print("033[0;34m[" + message + "\033[0;30m");
                        break;
                    default:
                        message = "[" + dateFormat.format(date) + "]- " + username + "-" + getSocketInfo(ClientSock) + name.get(new Integer(level)) + txt;
                        saveLogs(message, true);
                        System.out.println(message);
                        break;
                }
            } else {
                message = "[" + dateFormat.format(date) + "]- " + username + "-" + getSocketInfo(ClientSock) + name.get(new Integer(level)) + txt;
                saveLogs(message, false);
                System.out.println(message);
            }

        }
        FileWriter fileWriter;

        //flag =false logaccess; = true log active
        private void saveLogs(String txt, boolean flag) {
            try {
                if (flag == true) {
                    fileWriter = new FileWriter(_Log, true);
                } else {
                    fileWriter = new FileWriter(_AccessLog, true);
                }
                BufferedWriter bufferedWriter = new BufferedWriter(fileWriter);
                bufferedWriter.write(txt + EOL);
                bufferedWriter.close();
            } catch (Exception e) {
            }
        }

        //----------------------------------------------------------------------
        public static void setUser(String _user) {
            if (Logs.getLogger().isEnabled(Logger.INFO)) {
                Logs.getLogger().setUsername(_user);

            }
        }

        public void setLogUser() {
            setAccessLog();
            setLog();
        }

        //set accessLogs: log all authen session access to proxy or Web Server
        private void setAccessLog() {
            try {
                SimpleDateFormat format = new SimpleDateFormat("MMddyyyy");
                String ProxyLogDir = "proxy\\" + username + "\\accesslog-" + format.format(Calendar.getInstance().getTime());

                _AccessLog = new File(ProxyLogDir);

                if (_AccessLog.exists() == false) {
                    _AccessLog.getParentFile().mkdirs();
                }

            } catch (Exception e) {

            }
        }

        // Log all action when Client session to proy
        private void setLog() {
            try {
                SimpleDateFormat format = new SimpleDateFormat("MMddyyyy");
                String ProxyLogDir = "proxy\\" + username + "\\log-" + format.format(Calendar.getInstance().getTime());
                _Log = new File(ProxyLogDir);
                if (_Log.exists() == false) {
                    _Log.getParentFile().mkdirs();
                }

            } catch (Exception e) {

            }
        }

        public void logproxy(int level, String message, boolean bool) {
        }

        public void setLogProxy() {

        }

    }

    ////////////////////////////////////////////////////////////////////////////
    ////////////////////////////////////////////////////////////////////////////
    public static void setLogUsers() {
        Logs.getLogger().setLogUser();

    }

    public static void setLogProxys() {
        Logs.getLogger().setLogProxy();

    }

    //----------------------------------------------------------------------
    public static void Println(int level, String txt, boolean bool) {
        if (bool == true) {
            if (Logs.getLogger().isEnabled(level)) {
                Logs.getLogger().logclient(level, txt, true);
            }
        }
        if (bool == false) {
            if (Logs.getLogger().isEnabled(level)) {
                Logs.getLogger().logclient(level, txt, false);
            }
        }
    }

    public static void PrintlnProxy(int level, String txt, boolean bool) {
        if (bool == true) {
            if (Logs.getLogger().isEnabled(level)) {
                Logs.getLogger().logproxy(level, txt, true);
            }
        }
        if (bool == false) {
            if (Logs.getLogger().isEnabled(level)) {
                Logs.getLogger().logproxy(level, txt, false);
            }
        }
    }

    ////////////////////////////////////////////////////////////////////////////
    static String getSocketInfo(Socket Sock) {
        if (Sock == null) {
//            return "NA / NA:0";
            return "/NA:0";
        }
        String Info = "<" + IP2Str(Sock.getInetAddress()) + ":" + Sock.getPort() + ">";

        return Info;
    }

    ////////////////////////////////////////////////////////////////////////////
    public static String IP2Str(InetAddress IP) {
        if (IP == null) {
            return "NA/NA";
        }
        return IP.getHostName() + "/" + IP.getHostAddress();
    }
    ////////////////////////////////////////////////////////////////////////////

}
