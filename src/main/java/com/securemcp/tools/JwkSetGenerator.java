package com.securemcp.tools;
import com.nimbusds.jose.JWSAlgorithm; import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.RSAKey;

import java.security.*; import java.security.interfaces.*; import java.nio.file.*; import java.util.*;
/** Local key bootstrap utility. Keep generated private JWK material in Vault or a secret manager. */
public final class JwkSetGenerator {
 private JwkSetGenerator(){}
 public static void main(String[] args)throws Exception{
  if(args.length!=1)throw new IllegalArgumentException("Usage: JwkSetGenerator <output-file>");
  KeyPairGenerator generator=KeyPairGenerator.getInstance("RSA");generator.initialize(3072);KeyPair pair=generator.generateKeyPair();
  RSAKey key=new RSAKey.Builder((RSAPublicKey)pair.getPublic()).privateKey((RSAPrivateKey)pair.getPrivate()).keyID(UUID.randomUUID().toString()).algorithm(JWSAlgorithm.RS256).keyUse(KeyUse.SIGNATURE).build();
  Path output=Path.of(args[0]);Files.createDirectories(output.toAbsolutePath().getParent());new com.fasterxml.jackson.databind.ObjectMapper().writeValue(output.toFile(),new JWKSet(key).toJSONObject());
  try{Files.setPosixFilePermissions(output,java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));}catch(UnsupportedOperationException ignored){}
  System.out.println("Generated signing JWK set at "+output+". Treat this file as a private key; never commit it.");
 }
}
