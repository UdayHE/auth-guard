package io.github.UdayHE.authguard.service.implementation;

import io.github.UdayHE.authguard.repository.TokenRepository;
import io.github.UdayHE.authguard.service.JwtService;
import io.github.UdayHE.authguard.token.Token;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Service;

import static io.github.UdayHE.authguard.util.Constants.AUTH_GUARD_TOKEN;
import static io.github.UdayHE.authguard.util.Constants.BEARER;
import static java.util.Objects.nonNull;

@Service
@RequiredArgsConstructor
public class LogoutService implements LogoutHandler {

    private final TokenRepository tokenRepository;
    private final JwtService jwtService;

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response,
            Authentication authentication
    ) {
        final String authHeader = request.getHeader(AUTH_GUARD_TOKEN);
        final String jwt;
        if (authHeader == null || !authHeader.startsWith(BEARER))
            return;
        jwt = authHeader.substring(7);
        Token storedToken = tokenRepository.findByToken(jwt).orElse(null);
//        if (nonNull(storedToken)) {
//            String userName = jwtService.extractUsername(storedToken.getToken());
//            if (isNotBlank(userName))
//                tokenRepository.invalidateUserTokens(userName);
//            SecurityContextHolder.clearContext();
//        }

        if (nonNull(storedToken)) {
            storedToken.setExpired(true);
            storedToken.setRevoked(true);
            tokenRepository.save(storedToken);
            SecurityContextHolder.clearContext();
        }
    }
}