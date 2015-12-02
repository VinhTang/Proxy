package proxy;

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
    public static boolean ProxyLog = true;
    public static boolean ClientLog = true;
    //public static Properties Prop = null;
    public Logger log;

    public static boolean LoadProperties() {

//        if (Proxy_host == null || Proxy_host.length() <= 0 || Proxy_host_port <= 0) {
//            ErrorMsg = "Invaild setting for SSH Proxy ! Use of SSH Proxy Disabled !";
//            UseSSHProxy = false;
//        }
//        EnableLog = Tools.LoadBoolean("EnableLog", true, Prop);
        if (ProxyLog == true) {
            Logs.setLogger(new Logs.ProxyLog());

            Logs.PrintlnProxy(Logger.INFO, "Proxy SSH"
                    + "\n---------------------------------------\n"
                    + "    SOCKS Proxy Port : " + listen_Port
                    + "\n---------------------------------------\n");
        }
        return true;
    }
    //----------------------------------------------------------------

//----------------------------------------------------------------
    public static void main(String[] args) {
        if (!LoadProperties()) {
            return;
        }

        //SOCKServer SockSer =new SOCKServer(listen_Port,Proxy_host,Proxy_host_port);
        SOCKServer SockSer = new SOCKServer(listen_Port);
        SockSer.start();

    }

}
