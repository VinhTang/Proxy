package proxy;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Properties;
import SSHServer.HASH;

/**
 *
 * @author Milky_Way
 */
public class Tools {
////////////////////////////////////////////////////////////////////////////////

    public static final byte[] empty = str2byte("");

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

    //-------------------
    public static int byte2SInteger(Byte b) {
        int i = b.intValue();
        return i;
    }

    //-------------------
    public static String byte2str(byte[] b) {
        String str = new String(b, 0, b.length);
        return str;
    }

    //-------------------
    public static String byte2str(byte[] str, int s, int l) {
        return byte2str(str, s, l, "UTF-8");
    }

    //-------------------
    public static String byte2str(byte[] str, int s, int l, String encoding) {
        try {
            return new String(str, s, l, encoding);
        } catch (java.io.UnsupportedEncodingException e) {
            return new String(str, s, l);
        }
    }

    //-------------------
    public static byte[] str2byte(String str) {
        return str2byte(str, "UTF-8");
    }

    //-------------------
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

    //-------------------
    private static final byte[] b64 = Tools.str2byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=");

    private static byte val(byte foo) {
        if (foo == '=') {
            return 0;
        }
        for (int j = 0; j < b64.length; j++) {
            if (foo == b64[j]) {
                return (byte) j;
            }
        }
        return 0;
    }

    public static byte[] fromBase64(byte[] buf, int start, int length) {
        byte[] foo = new byte[length];
        int j = 0;
        for (int i = start; i < start + length; i += 4) {
            foo[j] = (byte) ((val(buf[i]) << 2) | ((val(buf[i + 1]) & 0x30) >>> 4));
            if (buf[i + 2] == (byte) '=') {
                j++;
                break;
            }
            foo[j + 1] = (byte) (((val(buf[i + 1]) & 0x0f) << 4) | ((val(buf[i + 2]) & 0x3c) >>> 2));
            if (buf[i + 3] == (byte) '=') {
                j += 2;
                break;
            }
            foo[j + 2] = (byte) (((val(buf[i + 2]) & 0x03) << 6) | (val(buf[i + 3]) & 0x3f));
            j += 3;
        }
        byte[] bar = new byte[j];
        System.arraycopy(foo, 0, bar, 0, j);
        return bar;
    }

    public static byte[] toBase64(byte[] buf, int start, int length) {

        byte[] tmp = new byte[length * 2];
        int i, j, k;

        int foo = (length / 3) * 3 + start;
        i = 0;
        for (j = start; j < foo; j += 3) {
            k = (buf[j] >>> 2) & 0x3f;
            tmp[i++] = b64[k];
            k = (buf[j] & 0x03) << 4 | (buf[j + 1] >>> 4) & 0x0f;
            tmp[i++] = b64[k];
            k = (buf[j + 1] & 0x0f) << 2 | (buf[j + 2] >>> 6) & 0x03;
            tmp[i++] = b64[k];
            k = buf[j + 2] & 0x3f;
            tmp[i++] = b64[k];
        }

        foo = (start + length) - foo;
        if (foo == 1) {
            k = (buf[j] >>> 2) & 0x3f;
            tmp[i++] = b64[k];
            k = ((buf[j] & 0x03) << 4) & 0x3f;
            tmp[i++] = b64[k];
            tmp[i++] = (byte) '=';
            tmp[i++] = (byte) '=';
        } else if (foo == 2) {
            k = (buf[j] >>> 2) & 0x3f;
            tmp[i++] = b64[k];
            k = (buf[j] & 0x03) << 4 | (buf[j + 1] >>> 4) & 0x0f;
            tmp[i++] = b64[k];
            k = ((buf[j + 1] & 0x0f) << 2) & 0x3f;
            tmp[i++] = b64[k];
            tmp[i++] = (byte) '=';
        }
        byte[] bar = new byte[i];
        System.arraycopy(tmp, 0, bar, 0, i);
        return bar;

//    return sun.misc.BASE64Encoder().encode(buf);
    }

    //-------------------
    public static String toHex(byte[] str) {
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < str.length; i++) {
            String foo = Integer.toHexString(str[i] & 0xff);
            sb.append("0x" + (foo.length() == 1 ? "0" : "") + foo);
            if (i + 1 < str.length) {
                sb.append(":");
            }
        }
        return sb.toString();
    }
////////////////////////////////////////////////////////////////////////////////

    public static boolean array_equals(byte[] foo, byte bar[]) {
        int i = foo.length;
        if (i != bar.length) {
            return false;
        }
        for (int j = 0; j < i; j++) {
            if (foo[j] != bar[j]) {
                return false;
            }
        }
        //try{while(true){i--; if(foo[i]!=bar[i])return false;}}catch(Exception e){}
        return true;
    }

    //------------------------
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

    //-------------------
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
            Logs.Println(Logger.ERROR, "calcInetAddress() - Invalid length of IP v4 - " + DST_Addr.length + " bytes");
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
    private static String[] chars = {
        "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f"
    };

    public static String getFingerPrint(HASH hash, byte[] data) {
        try {
            hash.init();
            hash.update(data, 0, data.length);
            byte[] foo = hash.digest();
            StringBuffer sb = new StringBuffer();
            int bar;
            for (int i = 0; i < foo.length; i++) {
                bar = foo[i] & 0xff;

                sb.append(chars[(bar >>> 4) & 0xf]);
                sb.append(chars[(bar) & 0xf]);
                if (i + 1 < foo.length) {
                    sb.append(":");
                }
            }
            return sb.toString();
        } catch (Exception e) {
            return "???";
        }
    }
////////////////////////////////////////////////////////////////////////////////

    public static void bzero(byte[] foo) {
        if (foo == null) {
            return;
        }
        for (int i = 0; i < foo.length; i++) {
            foo[i] = 0;
        }
    }
////////////////////////////////////////////////////////////////////////////////

    public static String checkTilde(String str) {
        try {
            if (str.startsWith("~")) {
                str = str.replace("~", System.getProperty("user.home"));
            }
        } catch (SecurityException e) {
        }
        return str;
    }

    public static byte[] fromFile(String _file) throws IOException {
        _file = checkTilde(_file);
        File file = new File(_file);
        FileInputStream fis = new FileInputStream(_file);
        try {
            byte[] result = new byte[(int) (file.length())];
            int len = 0;
            while (true) {
                int i = fis.read(result, len, result.length - len);
                if (i <= 0) {
                    break;
                }
                len += i;
            }
            fis.close();
            return result;
        } finally {
            if (fis != null) {
                fis.close();
            }
        }
    }
////////////////////////////////////////////////////////////////////////////////
}
