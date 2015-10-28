/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package ssh;

public class Packet {

    private static Cookie cookie = null;

    static void setRandom(Cookie foo) {
        cookie = foo;
    }

    Buffer buffer;
    byte[] ba4 = new byte[4];

    public Packet(Buffer buffer) {
        this.buffer = buffer;
    }

    public void reset() {
        buffer.index = 5;
    }

    void padding(int bsize) {
        int len = buffer.index;
        int pad = (-len) & (bsize - 1);
        if (pad < bsize) {
            pad += bsize;
        }
        len = len + pad - 4;
        ba4[0] = (byte) (len >>> 24);
        ba4[1] = (byte) (len >>> 16);
        ba4[2] = (byte) (len >>> 8);
        ba4[3] = (byte) (len);
        System.arraycopy(ba4, 0, buffer.buffer, 0, 4);
        buffer.buffer[4] = (byte) pad;
        synchronized (cookie) {
            cookie.fill(buffer.buffer, buffer.index, pad);
        }
        buffer.skip(pad);
    //buffer.putPad(pad);
/*
         for(int i=0; i<buffer.index; i++){
         System.err.print(Integer.toHexString(buffer.buffer[i]&0xff)+":");
         }
         System.err.println("");
         */
    }

    int shift(int len, int mac) {
        int s = len + 5 + 9;
        int pad = (-s) & 15;
        if (pad < 16) {
            pad += 16;
        }
        s += pad;
        s += mac;

        /**/
        if (buffer.buffer.length < s + buffer.index - 5 - 9 - len) {
            byte[] foo = new byte[s + buffer.index - 5 - 9 - len];
            System.arraycopy(buffer.buffer, 0, foo, 0, buffer.buffer.length);
            buffer.buffer = foo;
        }
        /**/

//if(buffer.buffer.length<len+5+9)
//  System.err.println("buffer.buffer.length="+buffer.buffer.length+" len+5+9="+(len+5+9));
//if(buffer.buffer.length<s)
//  System.err.println("buffer.buffer.length="+buffer.buffer.length+" s="+(s));
        System.arraycopy(buffer.buffer,
                len + 5 + 9,
                buffer.buffer, s, buffer.index - 5 - 9 - len);

        buffer.index = 10;
        buffer.putInt(len);
        buffer.index = len + 5 + 9;
        return s;
    }

    void unshift(byte command, int recipient, int s, int len) {
        System.arraycopy(buffer.buffer,
                s,
                buffer.buffer, 5 + 9, len);
        buffer.buffer[5] = command;
        buffer.index = 6;
        buffer.putInt(recipient);
        buffer.putInt(len);
        buffer.index = len + 5 + 9;
    }

    Buffer getBuffer() {
        return buffer;
    }
}
