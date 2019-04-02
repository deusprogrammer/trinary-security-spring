package com.trinary.security.token;

import java.util.HashMap;
import java.util.Map;

import com.trinary.security.entities.User;
import org.springframework.stereotype.Component;

@Component
public class MemoryResidentTokenManager extends TokenManager {
	protected static Map<String, Token> tokenMap = new HashMap<String, Token>();
	protected static Map<String, Token> userMap  = new HashMap<String, Token>();
	
	public MemoryResidentTokenManager(TokenFactory tokenFactory) {
		super(tokenFactory);
	}
	
	@Override
	protected Token getTokenByString(String tokenString) {
		synchronized(tokenMap) {
			return tokenMap.get(tokenString);
		}
	}
	
	@Override
	protected Token getTokenByPrincipal(User principal) {
		synchronized(userMap) {
			return userMap.get(principal.getUsername());
		}
	}
	
	@Override
	protected void storeToken(Token token) {
		synchronized(tokenMap) {
			tokenMap.put(token.getToken(), token);
		}
		synchronized(userMap) {
			userMap.put(token.getPrincipal().getUsername(), token);
		}
	}
	
	@Override
	protected Token releaseToken(Token token) {
		synchronized(tokenMap) {
			tokenMap.remove(token.getToken());
		}
		synchronized(userMap) {
			userMap.remove(token.getPrincipal().getUsername());
		}
		return token;
	}
}