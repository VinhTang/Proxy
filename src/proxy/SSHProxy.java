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
    
    public static boolean UseSSHProxy = true;
    public static boolean ProxyLog = true;
    public static boolean ClientLog = true;
    //public static Properties Prop = null;
    public Logger log;
    
    public static boolean LoadProperties() {
        
        if (ProxyLog == true) {
            Logger proxylog = new Logs.ProxyLog();
            Logs.setProxyLog(proxylog);
            Logs.setLogProxys();
            
            Logs.PrintlnProxy(Logger.INFO, "name:Proxy SSH; ListenPort:" + listen_Port + "; status: Start;", true);
            
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
