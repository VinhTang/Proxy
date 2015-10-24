/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package proxy;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Properties;

/**
 *
 * @author Milky_Way
 */
public class Tools {
////////////////////////////////////////////////////////////////////////////////

    public static boolean CheckBoolean(String temp, boolean Default) {
        temp = temp.toUpperCase();
        System.out.println("temp: " + temp);
        if (temp.equals("1")
                || temp.equals("TRUE")
                || temp.equals("YES")) {
            return true;
        }

        if (temp.equals("0")
                || temp.equals("FALSE")
                || temp.equals("NO")) {
            return false;
        }
        return Default;
    }
    ////////////////////////////////////////////////////////////////////////////

    public static boolean LoadBoolean(String Name, boolean Default, Properties Prop) {
        String temp = LoadString(Name, Prop); // tra về EnableLog
        if (temp == null) {
            return Default;
        }
        return CheckBoolean(temp, Default);

    }
    //---------------------

    public static String LoadString(String Name, Properties Prop) {
        return LoadString(Name, "", Prop);
    }

    //---------------------
    private static String LoadString(String Name, String Default, Properties Prop) {
        if (Prop == null) {
            return Default;
        }
        String Value;
        Value = Prop.getProperty(Name);
        System.out.println("Value: " + Value);
        if (Value == null) {
            return Default;
        }
        return Value;

    }

    ////////////////////////////////////////////////////////////////////////////
    public static int byte2int(byte b) {
        int res = b;
        if (res < 0) {
            res = (int) (0x100 + res); //0x100 = 256
        }
        return res;
    }

    public static int byte2SInteger(Byte b) {
        int i = b.intValue();
        return i;
    }

    public static String byte2String(byte[] b) {
        String str = new String(b, 0, b.length);
        return str;
    }

    public static byte[] str2byte(String str) {
        return str2byte(str, "UTF-8");
    }

    public static byte[] str2byte(String str, String encoding) {
        if (str == null) {
            return null;
        }
        try {
            return str.getBytes(encoding);
        } catch (java.io.UnsupportedEncodingException e) {
            return str.getBytes();
        }
    }
////////////////////////////////////////////////////////////////////////////////

    public static InetAddress calcInetAddress(byte[] DST_Addr) {
        InetAddress IA = null;
        String sIA = "";

        if (DST_Addr.length < 4) {
            Logs.Error("calcInetAddress() - Invalid length of IP v4 - " + DST_Addr.length + " bytes");
            return null;
        }

        // IP v4 Address Type
        for (int i = 0; i < 4; i++) {
            sIA += byte2int(DST_Addr[i]);
            if (i < 3) {
                sIA += ".";
            }
        }

        try {
            IA = InetAddress.getByName(sIA);
        } catch (UnknownHostException e) {
            return null;
        }

        return IA; // IP Address
    }

    //-------------------------
    public static int calcPort(byte[] DST_Port) {
        int port;
        port = byte2int(DST_Port[0]);
        port = port * 10 + byte2int(DST_Port[1]);
        return port;
    }
// qua VIP
//    public int calcPort(byte Hi, byte Lo) {
//
//        return ((byte2int(Hi) << 8) | byte2int(Lo));
//    }
////////////////////////////////////////////////////////////////////////////////
}
