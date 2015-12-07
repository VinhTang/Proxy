/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package proxy;

import java.sql.CallableStatement;
import java.sql.ResultSet;

/**
 *
 * @author Milky_Way
 */
public class DB_controller {

    public static void CheckUser(Proxy proxy, String User, String Pass, String Remotehost) throws Exception {
        Proxy _proxy = proxy;
        if (DB_controller.checkString(User) == true
                && DB_controller.checkString(Pass) == true) {
            Db_Connection.Open();
            Db_Connection.Open();
            CallableStatement cStmt = Db_Connection.con.prepareCall("{CALL checkUser(?,?,?)}");
            cStmt.setString(1, User);
            cStmt.setString(2, Pass);
            cStmt.setString(3, Remotehost);
            cStmt.execute();
            ResultSet rs = cStmt.getResultSet();
            if(rs.next()==true) {
                System.out.println(rs.getString("Permission") + " - "
                        + rs.getString("Username") + " - " + rs.getString("Password"));
            }
            rs.close();

        } else {
            _proxy.Close();
        }

    }

    //////////////////////////////////////////
    public static boolean checkString(String str) {
        return true;
    }
}
