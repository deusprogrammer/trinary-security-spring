package com.trinary.security.token;

import java.util.Date;

import com.trinary.security.entities.User;

public class Token {
	protected User principal;
	protected String token;
	protected Date expires;
	
	/**
	 * @return the principal
	 */
	public User getPrincipal() {
		return principal;
	}
	/**
	 * @param principal the principal to set
	 */
	public void setPrincipal(User principal) {
		this.principal = principal;
	}
	/**
	 * @return the token
	 */
	public String getToken() {
		return token;
	}
	/**
	 * @param token the token to set
	 */
	public void setToken(String token) {
		this.token = token;
	}
	/**
	 * @return the expires
	 */
	public Date getExpires() {
		return expires;
	}
	/**
	 * @param expires the expires to set
	 */
	public void setExpires(Date expires) {
		this.expires = expires;
	}
	
	public Boolean isExpired() {
		Date now = new Date();
		return expires.before(now);
	}
}