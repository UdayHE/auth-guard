package io.github.UdayHE.authguard.util;

/**
 * @author udayhegde
 */
import io.jsonwebtoken.security.Keys;
import lombok.experimental.UtilityClass;

import java.nio.charset.StandardCharsets;
import java.security.Key;

@UtilityClass
public class JWTUtil {
    private static final String SECRET_KEY_STR = "voice-vault-very-long-and-secure-key-that-is-at-least-32-characters";
    public static final Key SECRET_KEY = Keys.hmacShaKeyFor(SECRET_KEY_STR.getBytes(StandardCharsets.UTF_8));
    private static final long EXPIRATION_TIME = 86400000; // 24 hours in milliseconds
//    public static String generateToken(String username) {
//        return Jwts.builder()
//                .setSubject(username)
//                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
//                .signWith(SECRET_KEY, SignatureAlgorithm.HS512)
//                .compact();
//    }
//    public static String extractUsername(String token) {
//        return Jwts.parser()
//                .setSigningKey(SECRET_KEY)
//                .parseClaimsJws(token)
//                .getBody()
//                .getSubject();
//    }
}
