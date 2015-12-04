/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package proxy;

import java.util.Date;

/**
 *
 * @author Milky_Way
 */
public class Info {
////////////////////////////////////////////////////////////////////////////////

    private String UserID;
    private String Username;

    private int SockVer;
    private String Host;
    private int Hostport;

    private String UserSSH;
    private String RemoteHost;
    private int Remoteport;

    private Date datelogin;
    private Date dateout;
    private String cmd;

////////////////////////////////////////////////////////////////////////////////
    public String getUserID() {
        return UserID;
    }

    public void setUserID(String UserID) {
        this.UserID = UserID;
    }

    public String getUsername() {
        return Username;
    }

    public void setUsername(String Username) {
        this.Username = Username;
    }

    public int getSockVer() {
        return SockVer;
    }

    public void setSockVer(int SockVer) {
        this.SockVer = SockVer;
    }

    public String getHost() {
        return Host;
    }

    public void setHost(String Host) {
        this.Host = Host;
    }

    public int getHostport() {
        return Hostport;
    }

    public void setHostport(int Hostport) {
        this.Hostport = Hostport;
    }

    public String getUserSSH() {
        return UserSSH;
    }

    public void setUserSSH(String UserSSH) {
        this.UserSSH = UserSSH;
    }

    public String getRemoteHost() {
        return RemoteHost;
    }

    public void setRemoteHost(String RemoteHost) {
        this.RemoteHost = RemoteHost;
    }

    public int getRemoteport() {
        return Remoteport;
    }

    public void setRemoteport(int Remoteport) {
        this.Remoteport = Remoteport;
    }

    public Date getDatelogin() {
        return datelogin;
    }

    public void setDatelogin(Date datelogin) {
        this.datelogin = datelogin;
    }

    public Date getDateout() {
        return dateout;
    }

    public void setDateout(Date dateout) {
        this.dateout = dateout;
    }

    public String getCmd() {
        return cmd;
    }

    public void setCmd(String cmd) {
        this.cmd = cmd;
    }
}
