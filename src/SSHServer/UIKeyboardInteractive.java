/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package SSHServer;

public interface UIKeyboardInteractive {

    String[] promptKeyboardInteractive(String destination,
            String name,
            String instruction,
            String[] prompt,
            boolean[] echo);
}
