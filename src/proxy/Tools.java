package proxy;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
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

    public static String byte2str(byte[] str, int s, int l) {
        return byte2str(str, s, l, "UTF-8");
    }

    public static String byte2str(byte[] str, int s, int l, String encoding) {
        try {
            return new String(str, s, l, encoding);
        } catch (java.io.UnsupportedEncodingException e) {
            return new String(str, s, l);
        }
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

    public static String diffString(String str, String[] not_available) {
        String[] stra = Tools.split(str, ",");
        String result = null;
        loop:
        for (int i = 0; i < stra.length; i++) {
            for (int j = 0; j < not_available.length; j++) {
                if (stra[i].equals(not_available[j])) {
                    continue loop;
                }
            }
            if (result == null) {
                result = stra[i];
            } else {
                result = result + "," + stra[i];
            }
        }
        return result;
    }

    public static String[] split(String foo, String split) {
        if (foo == null) {
            return null;
        }
        byte[] buf = Tools.str2byte(foo);
        java.util.Vector bar = new java.util.Vector();
        int start = 0;
        int index;
        while (true) {
            index = foo.indexOf(split, start);
            if (index >= 0) {
                bar.addElement(Tools.byte2str(buf, start, index - start));
                start = index + 1;
                continue;
            }
            bar.addElement(Tools.byte2str(buf, start, buf.length - start));
            break;
        }
        String[] result = new String[bar.size()];
        for (int i = 0; i < result.length; i++) {
            result[i] = (String) (bar.elementAt(i));
        }
        return result;
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
