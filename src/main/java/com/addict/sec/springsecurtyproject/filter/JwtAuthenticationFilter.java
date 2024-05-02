package com.addict.sec.springsecurtyproject.filter;

import java.io.IOException;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.addict.sec.springsecurtyproject.service.JwTService;
import com.addict.sec.springsecurtyproject.service.UserService;

import io.micrometer.common.lang.NonNull;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter{
    
    
    private final JwTService jwtservice;
    
    
    private final UserService userDetailService;
    
    

    


    public JwtAuthenticationFilter(JwTService jwtservice, UserService userDetailService) {
        this.jwtservice = jwtservice;
        this.userDetailService = userDetailService;
    }






    @Override
    protected void doFilterInternal( @NonNull HttpServletRequest request,  @NonNull HttpServletResponse response,  @NonNull FilterChain filterChain)
            throws ServletException, IOException {

            String authHeader = request.getHeader("Authorization");

            if(authHeader == null || !authHeader.startsWith("Bearer ")){
                filterChain.doFilter(request, response);
                return;
            }

            String token  = authHeader.substring(7);
            String username = jwtservice.extractUsername(token);

            if(username !=null && SecurityContextHolder.getContext().getAuthentication()==null){
                UserDetails userDetails = userDetailService.loadUserByUsername(username);

                
                if(jwtservice.isValid(token, userDetails)) {
                    UsernamePasswordAuthenticationToken authtoken = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities()
                    );
                    

                authtoken.setDetails(
                    new WebAuthenticationDetailsSource().buildDetails(request)
                );

                SecurityContextHolder.getContext().setAuthentication(authtoken);
                    
                
            }
        }

            filterChain.doFilter(request, response);
        
    
        }

            }
        
