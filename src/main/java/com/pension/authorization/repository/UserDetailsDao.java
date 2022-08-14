/**
 * 
 */
package com.pension.authorization.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.pension.authorization.model.User;

/**
 * @author SAYANDIP PAUL
 *
 */
@Repository
public interface UserDetailsDao extends JpaRepository<User, Integer>{

	public User findByUsername(String userName);
}
