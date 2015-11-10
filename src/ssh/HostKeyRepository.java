/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package ssh;

public interface HostKeyRepository{
  final int OK=0;
  final int NOT_INCLUDED=1;
  final int CHANGED=2;

  int check(String host, byte[] key);
  void add(HostKey hostkey, UserInfo ui);
  void remove(String host, String type);
  void remove(String host, String type, byte[] key);
  String getKnownHostsRepositoryID();
  HostKey[] getHostKey();
  HostKey[] getHostKey(String host, String type);
}
