/**
 * 
 */
package com.pension.authorization.model;

import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;

/**
 * @author SAYANDIP PAUL
 *
 */
@NoArgsConstructor
@AllArgsConstructor
public class JwtRequest {

	private String username;
	private String password;
	/**
	 * @return the userName
	 */
	public String getUsername() {
		return username;
	}
	/**
	 * @param userName the userName to set
	 */
	public void setUsername(String username) {
		this.username = username;
	}
	/**
	 * @return the password
	 */
	public String getPassword() {
		return password;
	}
	/**
	 * @param password the password to set
	 */
	public void setPassword(String password) {
		this.password = password;
	}
	
}
