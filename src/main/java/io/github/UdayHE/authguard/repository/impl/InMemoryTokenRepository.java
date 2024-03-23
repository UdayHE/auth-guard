package io.github.UdayHE.authguard.repository.impl;

import io.github.UdayHE.authguard.repository.TokenRepository;
import io.github.UdayHE.authguard.token.Token;
import org.springframework.stereotype.Repository;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

@Repository
public class InMemoryTokenRepository implements TokenRepository {
    private Map<String, Token> tokens = new ConcurrentHashMap<>();

    @Override
    public void save(Token token) {
        tokens.put(token.getToken(), token);
    }

    @Override
    public Optional<Token> findByToken(String token) {
        return Optional.of(tokens.get(token));
    }

    @Override
    public Token findByUsername(String username) {
        return tokens.values().stream()
                .filter(token -> token.getUsername().equals(username))
                .findFirst()
                .orElse(null);
    }

    @Override
    public void deleteToken(String token) {
        tokens.remove(token);
    }

    @Override
    public void invalidateUserTokens(String username) {
        var tokensToRemove = tokens.values().stream()
                .filter(token -> token.getUsername().equals(username))
                .map(Token::getToken)
                .toList();
        tokensToRemove.forEach(tokens::remove);
    }

    @Override
    public void saveAll(List<Token> validUserTokens) {
        Map<String, Token> validTokens = validUserTokens.stream()
                .collect(Collectors.toConcurrentMap(Token::getToken, token -> token));
        tokens.putAll(validTokens);
    }

    @Override
    public List<Token> findAllValidTokenByUser(String username) {
        List<Token> validTokens = new ArrayList<>();
        for(Map.Entry<String, Token> entry : tokens.entrySet()) {
           Token token =  entry.getValue();
           if(token.getUsername().equals(username) &&
                   !token.isExpired() && !token.isRevoked()) {
               validTokens.add(token);
           }
        }
        return validTokens;
    }
}
