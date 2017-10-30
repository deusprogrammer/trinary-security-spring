package com.trinary.security.token;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.util.Base64;
import java.util.UUID;

import com.trinary.security.entities.User;
import com.trinary.security.utils.TimeUtils;

public class SHA1TokenFactory extends TokenFactory {

	@Override
	public Token generateToken(User principal) {
		MessageDigest digest;
		String uuid = UUID.randomUUID().toString();
		
		try {
			digest = MessageDigest.getInstance("SHA-1");
		} catch (NoSuchAlgorithmException e) {
			return null;
		}
		
		digest.update(String.format("%d:%s", principal.hashCode(), uuid).getBytes());
		
		Token token = new Token();
		token.setPrincipal(principal);
		token.setToken(Base64.getEncoder().encodeToString(digest.digest()).replaceAll("/", "_"));
		try {
			token.setExpires(TimeUtils.getLaterDate("24 hours"));
		} catch (ParseException e) {
			return null;
		}
		
		return token;
	}

}