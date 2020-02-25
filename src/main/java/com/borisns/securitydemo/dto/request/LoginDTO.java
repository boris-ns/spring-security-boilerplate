package com.borisns.securitydemo.dto.request;

import javax.validation.constraints.NotNull;

public class LoginDTO {

    @NotNull(message = "Username is required")
    private String username;

    @NotNull(message = "Password is required")
    private String password;

    public LoginDTO() {
        super();
    }

    public LoginDTO(String username, String password) {
        this.username = username;
        this.password = password;
    }

    public String getUsername() {
        return this.username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return this.password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
