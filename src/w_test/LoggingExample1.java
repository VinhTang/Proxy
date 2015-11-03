/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package w_test;

/**
 *
 * @author Milky_Way
 */
import java.util.logging.FileHandler;
import java.util.logging.Level;
import java.util.logging.LogManager;
import java.util.logging.Logger;
import java.util.logging.XMLFormatter;
public class LoggingExample1 {
public static void main(String args[]) {
    try {
      LogManager lm = LogManager.getLogManager();
      Logger logger;
      FileHandler fh = new FileHandler("log_test.txt");

      logger = Logger.getLogger("LoggingExample1");

      lm.addLogger(logger);
      logger.setLevel(Level.INFO);
      fh.setFormatter(new XMLFormatter());

      logger.addHandler(fh);
      // root logger defaults to SimpleFormatter. We don't want messages
      // logged twice.
      //logger.setUseParentHandlers(false);
      logger.log(Level.INFO, "test 1");
      logger.log(Level.INFO, "test 2");
      logger.log(Level.INFO, "test 3");
      fh.close();
    } catch (Exception e) {
      System.out.println("Exception thrown: " + e);
      e.printStackTrace();
    }
  }
}
