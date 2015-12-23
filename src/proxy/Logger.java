package proxy;

import java.io.File;
import java.io.FileNotFoundException;

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

    public void setUsername(String user);

    public void setLogProxy();

    public void setLogUser();

    public void logproxy(int level, String message, boolean bool);

    public void logclient(int level, String message, boolean bool);
}
