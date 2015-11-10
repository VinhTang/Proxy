package ssh;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 *
 * @author Milky_Way
 */
public class ProxyException extends Exception {

    //private static final long serialVersionUID=-1319309923966731989L;

    private Throwable cause = null;

    public ProxyException() {
        super();
    }

    public ProxyException(String s) {
        super(s);
    }

    public ProxyException(String s, Throwable e) {
        super(s);
        this.cause = e;
    }

    public Throwable getCause() {
        return this.cause;
    }
}


