package com.securemcp.config;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.userdetails.*;
import org.springframework.stereotype.Service;

@Service
public class DatabaseUserDetailsService implements UserDetailsService {
    private final JdbcTemplate jdbc;

    public DatabaseUserDetailsService(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @Override
    public UserDetails loadUserByUsername(String username) {
        return jdbc.query("select username,password_hash,enabled from app_users where username=?", rs -> {
            if (!rs.next()) throw new UsernameNotFoundException(username);
            return User.withUsername(rs.getString(1)).password(rs.getString(2)).disabled(!rs.getBoolean(3)).roles("USER").build();
        }, username);
    }
}
