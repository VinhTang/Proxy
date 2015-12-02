/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package SSHServer;

abstract class Request{
  private boolean reply=false;
  private sshServer session=null;
  private Channel channel=null;
  void request(sshServer session, Channel channel) throws Exception{
    this.session=session;
    this.channel=channel;
    if(channel.connectTimeout>0){
      setReply(true);
    }
  }
  boolean waitForReply(){ return reply; }
  void setReply(boolean reply){ this.reply=reply; }
  void write(Packet packet) throws Exception{
    if(reply){
      channel.reply=-1;
    }
    session.write(packet);
    if(reply){
      long start=System.currentTimeMillis();
      long timeout=channel.connectTimeout;
      while(channel.isConnected() && channel.reply==-1){
	try{Thread.sleep(10);}
	catch(Exception ee){
	}
        if(timeout>0L &&
           (System.currentTimeMillis()-start)>timeout){
          channel.reply=0;
          throw new ProxyException("channel request: timeout");
        }
      }

      if(channel.reply==0){
	throw new ProxyException("failed to send channel request");
      }
    }
  }
}
