/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package ssh;

public interface PBKDF {

    byte[] getKey(byte[] pass, byte[] salt, int iteration, int size);
}
