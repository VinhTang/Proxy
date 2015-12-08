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
public class test__________ {

    public static void main(String[] args) throws Exception {
        Db_Connection.Open();
        CallableStatement cStmt = Db_Connection.con.prepareCall("{CALL checkUser(?,?,?)}");
        cStmt.setString(1, "vinh");
        cStmt.setString(2, "12345");
        cStmt.setString(3, "192.168.10.111");
        cStmt.execute();
        ResultSet rs = cStmt.getResultSet();
        while (rs.next()) {
            System.out.println(rs.getInt("Permission") + " -"
                    + rs.getString("Username")+ " - "+ rs.getString("Password"));
        }
        rs.close();

    }
}
