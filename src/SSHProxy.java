/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 *
 * @author Milky_Way
 */
//---------------------------------------------
import proxy.SOCKServer;
import proxy.Logs;
import java.util.Properties;
import proxy.*;
//---------------------------------------------

public class SSHProxy {

    /**
     * @param args the command line arguments
     */
    public static final int DEFAULT_PORT = 1080;
    public static int listen_Port = DEFAULT_PORT;

    //public static String Proxy_host = "192.168.10.111";
    //public static int Proxy_host_port = 22;
    public static boolean UseSSHProxy = true;

    public static boolean EnableLog = true;
    public static Properties Prop = null;

    public static boolean LoadProperties() {
        String ErrorMsg = "";

        Prop = new Properties();

//        if (Proxy_host == null || Proxy_host.length() <= 0 || Proxy_host_port <= 0) {
//            ErrorMsg = "Invaild setting for SSH Proxy ! Use of SSH Proxy Disabled !";
//            UseSSHProxy = false;
//        }
        EnableLog = Tools.LoadBoolean("EnableLog", true, Prop);

        if (EnableLog) {
            Logs.Println("Logging: On");
        } else {
            Logs.Println("Logging: Off");
        }
        Logs.Println("---------------------------------------");
        Logs.Println("SOCKS Proxy Port : " + listen_Port);
        Logs.Println("---------------------------------------");
        return true;
    }

    public static void main(String[] args) {
        if (!LoadProperties()) {
            return;
        }
        Logs.EnableLog = EnableLog;
        
        //SOCKServer SockSer =new SOCKServer(listen_Port,Proxy_host,Proxy_host_port);
        SOCKServer SockSer =new SOCKServer(listen_Port);
        SockSer.start();
        
        
    }

}
