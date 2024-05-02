package com.addict.sec.springsecurtyproject.service;

import java.util.Date;
import java.util.function.Function;

import javax.crypto.SecretKey;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import com.addict.sec.springsecurtyproject.model.User;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;


@Service
public class JwTService {

    private final String SECRET_KEY = "bcbbcb701c8e70c2b7be64966da75b0b70bde3f415da335d539e03df59c6e191a03740e46479fdb07437de2b8ba39743db34b4404a9db701fd952c4a297ce35f4fde1ec01560f1759a57a89ad863d164a29c9be3d45408c12cd506e215fa6416828a711907f280adf04daeb236f14acc6385fd3b70738455adb2f8d2b61489fb99db2dd1e00e7a95600ea9947b2cb0dd926df1e0c4a62ebe5b790066c1ef939ee1e34ff26a8a333ece2f272741dc3ab77d5905b8cbb8392fcbcdecb80af39710eff98e8bc43f09a485ea7f64c3b42b775e3211c26331bda08418b2f2fdb60218d4db129d509b5b7a9e19be8d169c3fd8b37f9776f163dfb7a47ab775cdedbad5";
    
    
    public String extractUsername(String token)
    {
        return extractClaim(token,Claims::getSubject);
    }

    public boolean isValid(String token, UserDetails user){
        String username = extractUsername(token);

        return (username.equals(user.getUsername())) && !isTokenExpired(token);
    }




    private boolean isTokenExpired(String token) {
       return extractExpiration(token).before(new Date());
       
    }

    private Date extractExpiration(String token) {
       return extractClaim(token, Claims::getExpiration);
    }

    public <T> T extractClaim(String token, Function<Claims,T> resolver){

        Claims claims = extractAllClaims(token);
        return resolver.apply(claims);


    }

    
    private Claims extractAllClaims(String token){
        return Jwts
              .parser()
              .verifyWith(getSigninKey())
              .build()
              .parseSignedClaims(token)
              .getPayload();
    }


    public String generateToken(User user){
        String token = Jwts
                .builder()
                .subject(user.getUsername())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis()+24*60*60*1000))
                .signWith(getSigninKey())
                .compact();
                
        return token;        
    }




    private SecretKey getSigninKey() {
        byte[] keyBytes = Decoders.BASE64URL.decode(SECRET_KEY);
        
        return Keys.hmacShaKeyFor(keyBytes);
    }
    
}
