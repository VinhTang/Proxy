package ssh;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */


public interface Compression{
  static public final int INFLATER=0;
  static public final int DEFLATER=1;
  void init(int type, int level);
  int compress(byte[] buf, int start, int len);
  byte[] uncompress(byte[] buf, int start, int[] len);
}
