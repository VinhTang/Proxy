/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package proxy;

import java.sql.*;


public class Db_Connection {

    static Connection con;
    static Statement stm;

    public static void Open() throws Exception{
        Class.forName("com.mysql.jdbc.Driver").newInstance();
        con = DriverManager.getConnection("jdbc:mysql://localhost:3306/proxy", "root", "123");
        stm = con.createStatement();
    }

    public static void Close() throws Exception {
        con.close();
        stm.close();
    }
}
