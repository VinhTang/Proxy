/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package ssh;

public interface UserInfo {

    String getPassphrase();

    String getPassword();

    boolean promptPassword(String message);

    boolean promptPassphrase(String message);

    boolean promptYesNo(String message);

    void showMessage(String message);
}
