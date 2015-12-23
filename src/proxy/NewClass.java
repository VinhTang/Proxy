/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package proxy;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import static proxy.Logs.ClientLog.username;
import static proxy.Logs.ClientLog.writer;

/**
 *
 * @author Milky_Way
 */
public class NewClass {

    private static Object timeStamp;

    public static void main(String[] args) throws FileNotFoundException, UnsupportedEncodingException, IOException, InterruptedException {
        SimpleDateFormat format = new SimpleDateFormat("MMddyyyy");

        String ProxyLogDir = "SSHproxy\\" + "TEST" + "\\log-" + format.format(Calendar.getInstance().getTime());
        System.err.println("ProxyLogDir:" + ProxyLogDir);
        File log = new File(ProxyLogDir);
        log.getParentFile().mkdirs();
        if (log.exists() && !log.isDirectory()) {
            System.err.println("vao");
        }
        try {

            FileWriter fileWriter = new FileWriter(log, true);
            BufferedWriter bufferedWriter = new BufferedWriter(fileWriter);
            bufferedWriter.write("******* " + ProxyLogDir + "******* " + "\n");
            bufferedWriter.close();

            fileWriter = new FileWriter(log, true);
            bufferedWriter = new BufferedWriter(fileWriter);
            bufferedWriter.write("******asasas* " + ProxyLogDir + "******* " + "\n");
            bufferedWriter.close();
            System.out.println("Done");
        } catch (IOException e) {
            System.out.println("COULD NOT LOG!!" + e.toString());
        }

    }

}
