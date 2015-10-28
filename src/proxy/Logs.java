package proxy;



import java.net.BindException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.Socket;

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
    public static boolean EnableLog = true;

    ////////////////////////////////////////////////////////////////////////////
    public static void Println(String txt) {
        if (EnableLog) {
            Print(txt + EOL);
        }
    }

    public static void Print(String txt) {
        if (!EnableLog) {
            return;
        }
        if (txt == null) {
            return;
        }
        System.out.print(txt);
    }
    ////////////////////////////////////////////////////////////////////////////

    public static void Error(String txt) {
        if (EnableLog) {
            Println("Error : " + txt);
        }
    }

    public static void Error(Exception e) {
        if (!EnableLog) {
            return;
        }
        Println("ERROR : " + e.toString());
        e.printStackTrace();

    }
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
        return "Hostname: " + IP.getHostName() + " / "+IP.getHostAddress() ;
    }
}
