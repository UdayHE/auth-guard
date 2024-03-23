package io.github.UdayHE.authguard.repository;

import org.springframework.security.core.userdetails.UserDetails;

import java.util.Optional;

/**
 * @author udayhegde
 */
public interface UserRepository {
    Optional<UserDetails> findByUserName(String username);

    UserDetails save(UserDetails userDetails);

    void clear();

    Optional<UserDetails> removeByUserName(String userName);
}
