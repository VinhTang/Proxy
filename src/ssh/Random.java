package ssh;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */


import java.security.SecureRandom;


public class Random implements ssh.Cookie{
  private byte[] tmp=new byte[16];
  private SecureRandom random;
  public Random(){
    random=null;
    try{ random=SecureRandom.getInstance("SHA1PRNG"); }
    catch(java.security.NoSuchAlgorithmException e){ 
      // System.err.println(e); 

      // The following code is for IBM's JCE
      try{ random=SecureRandom.getInstance("IBMSecureRandom"); }
      catch(java.security.NoSuchAlgorithmException ee){ 
	System.err.println(ee); 
      }
    }
  }
  public void fill(byte[] foo, int start, int len){
    if(len>tmp.length){ tmp=new byte[len]; }
    random.nextBytes(tmp);
    System.arraycopy(tmp, 0, foo, start, len);
  }
}