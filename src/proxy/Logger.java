package proxy;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 *
 * @author Milky_Way
 */
public interface Logger {

    public final int DEBUG = 0;
    public final int INFO = 1;
    public final int WARN = 2;
    public final int ERROR = 3;
    public final int FATAL = 4;

    public boolean isEnabled(int level);

    public void logproxy(int level, String message);
    public void logclient(int level, String message);
}