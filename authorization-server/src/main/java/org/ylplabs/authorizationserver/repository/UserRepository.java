package org.ylplabs.authorizationserver.repository;

import org.springframework.cache.annotation.Cacheable;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import org.ylplabs.authorizationserver.domain.AppUser;

import java.util.Optional;

/**
 * Spring Data JPA repository for the {@link AppUser} entity.
 */
@Repository
public interface UserRepository extends JpaRepository<AppUser, Long> {

    String USERS_BY_USERNAME_CACHE = "usersByUsername";

    @Cacheable(cacheNames = USERS_BY_USERNAME_CACHE)
    @EntityGraph(attributePaths = {"authorities"})
    Optional<AppUser> findOneWithAuthoritiesByEmail(String email);

    @Cacheable(cacheNames = USERS_BY_USERNAME_CACHE)
    @EntityGraph(attributePaths = {"authorities"})
    Optional<AppUser> findOneWithAuthoritiesByUsername(String username);

}
