package io.github.UdayHE.authguard.repository.impl;

import io.github.UdayHE.authguard.repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Repository;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * @author udayhegde
 */
@Repository
public class InMemoryUserRepository implements UserRepository {

    private Map<String, UserDetails> userDetailsMap = new ConcurrentHashMap<>();

    @Override
    public Optional<UserDetails> findByUserName(String username) {
        return Optional.of(userDetailsMap.get(username));
    }

    @Override
    public UserDetails save(UserDetails userDetails) {
        userDetailsMap.put(userDetails.getUsername(), userDetails);
        return userDetails;
    }

    @Override
    public void clear() {
        userDetailsMap.clear();
    }

    @Override
    public Optional<UserDetails> removeByUserName(String userName) {
        return Optional.of(userDetailsMap.remove(userName));
    }
}
