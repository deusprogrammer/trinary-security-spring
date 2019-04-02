package com.trinary.security.token;

public class TokenManagerFactory {
	private static TokenManager tokenManager = null;
	
	public static TokenManager getTokenManager() {
		if (tokenManager == null) {
			tokenManager = new MemoryResidentTokenManager(new SHA1TokenFactory());
		}
		return tokenManager;
	}
}