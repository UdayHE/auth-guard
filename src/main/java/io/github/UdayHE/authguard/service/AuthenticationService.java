package io.github.UdayHE.authguard.service;

import io.github.UdayHE.authguard.dto.AuthenticationRequest;
import io.github.UdayHE.authguard.dto.AuthenticationResponse;
import io.github.UdayHE.authguard.dto.RegisterRequest;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

/**
 * @author udayhegde
 */
public interface AuthenticationService {

    AuthenticationResponse register(RegisterRequest request);
    AuthenticationResponse authenticate(AuthenticationRequest request) throws Throwable;
    void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException;

}
