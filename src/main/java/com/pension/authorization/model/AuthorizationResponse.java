/**
 * 
 */
package com.pension.authorization.model;

/**
 * @author SAYANDIP PAUL
 *
 */
public class AuthorizationResponse {
	
	private String token;
	private String message;
	private int statusCode;
	
	public AuthorizationResponse() {
		super();
	}
	public AuthorizationResponse(String token, String message, int statusCode) {
		super();
		this.token = token;
		this.message = message;
		this.statusCode = statusCode;
	}
	public String getToken() {
		return token;
	}
	public void setToken(String token) {
		this.token = token;
	}
	public String getMessage() {
		return message;
	}
	public void setMessage(String message) {
		this.message = message;
	}
	public int getStatusCode() {
		return statusCode;
	}
	public void setStatusCode(int statusCode) {
		this.statusCode = statusCode;
	}
	@Override
	public String toString() {
		return "AuthorizationResponse [token=" + token + ", message=" + message + ", statusCode=" + statusCode + "]";
	}
	
}
