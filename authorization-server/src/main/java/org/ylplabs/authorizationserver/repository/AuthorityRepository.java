package org.ylplabs.authorizationserver.repository;


import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;
import org.ylplabs.authorizationserver.domain.Authority;

import java.util.List;
import java.util.Set;

/**
 * Spring Data JPA repository for the {@link Authority} entity.
 */
@Repository
@Transactional(readOnly = true)
public interface AuthorityRepository extends JpaRepository<Authority, String> {

    List<Authority> findAllByNameIsIn(Set<String> names);
}
