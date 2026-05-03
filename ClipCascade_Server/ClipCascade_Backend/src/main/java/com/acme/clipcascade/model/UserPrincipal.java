package com.acme.clipcascade.model;

import java.io.Serializable;
import java.util.Collection;
import java.util.Collections;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.acme.clipcascade.constants.RoleConstants;
import com.acme.clipcascade.service.BruteForceProtectionService;

public class UserPrincipal implements UserDetails, Serializable {

    // duohub fork：spring-session-jdbc 持久化 session 时会序列化 SecurityContext
    // → Authentication → principal (UserPrincipal)。必须能被序列化。
    private static final long serialVersionUID = 1L;

    private Users user;

    // Spring service bean，不可序列化 + 也不应该跟 user 一起持久化。
    // transient 让它不被 Java 原生序列化触碰；反序列化后值为 null，
    // 由 isAccountNonLocked() 的 null 保护处理。
    private final transient BruteForceProtectionService bruteForceProtectionService;

    public UserPrincipal(
            Users user,
            BruteForceProtectionService bruteForceProtectionService) {

        this.user = user;
        this.bruteForceProtectionService = bruteForceProtectionService;
    }

    @Override
    public boolean isAccountNonLocked() {

        // duohub fork：反序列化场景（持久化 session 恢复）service 为 null。
        // brute force check 的目的是限制登录爆破，已建立的 session 恢复阶段
        // 已经过了认证，跳过 check 合理。新登录请求会走 MyUserDetailsService
        // 创建一个全新带 service 引用的 UserPrincipal，那时 check 仍生效。
        if (bruteForceProtectionService == null) {
            return true;
        }

        // validate attempt using brute force protection
        return bruteForceProtectionService.recordAndValidateAttempt(user.getUsername());
    }

    @Override
    public boolean isEnabled() {
        return user.getEnabled();
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // Return a collection of roles
        return Collections.singleton(new SimpleGrantedAuthority(user.getRole()));
    }

    public boolean isAdmin() {
        return this.getAuthorities().stream()
                .anyMatch(authority -> authority.getAuthority()
                        .strip()
                        .equalsIgnoreCase(RoleConstants.ADMIN));
    }

    public boolean isUser() {
        return this.getAuthorities().stream()
                .anyMatch(authority -> authority.getAuthority()
                        .strip()
                        .equalsIgnoreCase(RoleConstants.USER));
    }
}
