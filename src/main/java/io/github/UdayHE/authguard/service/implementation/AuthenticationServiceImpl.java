package io.github.UdayHE.authguard.service.implementation;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.UdayHE.authguard.dto.AuthenticationRequest;
import io.github.UdayHE.authguard.dto.AuthenticationResponse;
import io.github.UdayHE.authguard.dto.RegisterRequest;
import io.github.UdayHE.authguard.repository.TokenRepository;
import io.github.UdayHE.authguard.repository.UserRepository;
import io.github.UdayHE.authguard.service.AuthenticationService;
import io.github.UdayHE.authguard.service.JwtService;
import io.github.UdayHE.authguard.token.Token;
import io.github.UdayHE.authguard.token.TokenType;
import io.jsonwebtoken.security.SecurityException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.List;

import static io.github.UdayHE.authguard.util.Constants.BEARER;

@Service
@RequiredArgsConstructor
public class AuthenticationServiceImpl implements AuthenticationService {

    private final UserRepository repository;
    private final TokenRepository tokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    @Override
    public AuthenticationResponse register(RegisterRequest request) {
        UserDetails user = User.builder()
                .username(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .roles(request.getRole())
                .build();
        UserDetails savedUser = repository.save(user);
        String jwtToken = jwtService.generateToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);
        saveUserToken(savedUser, jwtToken);
        return AuthenticationResponse.builder()
                .accessToken(jwtToken).refreshToken(refreshToken).build();
    }

    @Override
    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        UserDetails user = repository.findByUserName(request.getEmail()).orElseThrow(() -> new UsernameNotFoundException("User Not Found"));
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()));
        if(authentication.isAuthenticated()) {
            String jwtToken = jwtService.generateToken(user);
            String refreshToken = jwtService.generateRefreshToken(user);
            revokeAllUserTokens(user);
            saveUserToken(user, jwtToken);
            return AuthenticationResponse.builder().accessToken(jwtToken)
                    .refreshToken(refreshToken).build();
        }
        throw new SecurityException("Invalid Credentials");
    }

    @Override
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        final String refreshToken;
        final String userEmail;
        if (authHeader == null || !authHeader.startsWith(BEARER))
            return;
        refreshToken = authHeader.substring(7);
        userEmail = jwtService.extractUsername(refreshToken);
        if (userEmail != null) {
          UserDetails user = this.repository.findByUserName(userEmail)
                    .orElseThrow();
            if (jwtService.isTokenValid(refreshToken, user)) {
              String accessToken = jwtService.generateToken(user);
                revokeAllUserTokens(user);
                saveUserToken(user, accessToken);
              AuthenticationResponse authResponse = AuthenticationResponse.builder()
                        .accessToken(accessToken)
                        .refreshToken(refreshToken)
                        .build();
                new ObjectMapper().writeValue(response.getOutputStream(), authResponse);
            }
        }
    }

    private void saveUserToken(UserDetails user, String jwtToken) {
        Token token = Token.builder()
                .username(user.getUsername())
                .token(jwtToken)
                .tokenType(TokenType.BEARER)
                .expired(false)
                .revoked(false)
                .build();
        tokenRepository.save(token);
    }

    private void revokeAllUserTokens(UserDetails user) {
        List<Token> validUserTokens = tokenRepository.findAllValidTokenByUser(user.getUsername());
        if (validUserTokens.isEmpty())
            return;
        validUserTokens.forEach(token -> {
            token.setExpired(true);
            token.setRevoked(true);
        });
        tokenRepository.saveAll(validUserTokens);
      //  tokenRepository.invalidateUserTokens(user.getUsername());
    }


}
