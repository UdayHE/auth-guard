package io.github.UdayHE.authguard.repository;


import io.github.UdayHE.authguard.token.Token;

import java.util.List;
import java.util.Optional;

/**
 * @author udayhegde
 */
public interface TokenRepository {


    void save(Token token);

    Optional<Token> findByToken(String token);

    Token findByUsername(String username);

    void deleteToken(String token);

    void invalidateUserTokens(String username);

    void saveAll(List<Token> validUserTokens);

    List<Token> findAllValidTokenByUser(String username);
}
