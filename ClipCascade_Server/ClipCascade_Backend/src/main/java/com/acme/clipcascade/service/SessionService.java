package com.acme.clipcascade.service;

import java.util.Map;

import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.session.Session;
import org.springframework.stereotype.Service;

import com.acme.clipcascade.utils.UserValidator;

import jakarta.persistence.EntityNotFoundException;

@Service
public class SessionService {

    // duohub fork：原实现走 SessionRegistry.getAllPrincipals()，但
    // SpringSessionBackedSessionRegistry 在 spring-session-core 里直接抛
    // UnsupportedOperationException（"Spring Session provides no way to obtain that information"）。
    // 任何 changeUsername/changePassword/Logoff All/admin 删用户的链路都会 500。
    //
    // 改成直接通过 FindByIndexNameSessionRepository.findByPrincipalName(username)
    // 拿到该用户名所有 session（PRINCIPAL_NAME 是 SPRING_SESSION 表的索引列），然后
    // sessionRepository.deleteById 删除。语义跟原 expireNow 一致——客户端 cookie 失效。

    private final FindByIndexNameSessionRepository<? extends Session> sessionRepository;
    private final UserService userService;

    public SessionService(
            FindByIndexNameSessionRepository<? extends Session> sessionRepository,
            UserService userService) {

        this.sessionRepository = sessionRepository;
        this.userService = userService;
    }

    // logout all sessions for a specific user/username
    public String logoutAllSessions(String username) {
        if (!UserValidator.isValidUsername(username)) {
            throw new IllegalArgumentException("Invalid username");
        }

        // Check if user exists
        if (!userService.userExists(username)) {
            throw new EntityNotFoundException("User not found");
        }

        // 直接按 principal name 拿 session（spring-session 的 indexed query）
        Map<String, ? extends Session> sessions = sessionRepository.findByPrincipalName(username);

        if (sessions.isEmpty()) {
            return "No active sessions found for username: " + username;
        }

        // 删除每个 session 即让对应 cookie 失效
        for (String sessionId : sessions.keySet()) {
            sessionRepository.deleteById(sessionId);
        }

        return "User '" + username + "' has been logged out of all active sessions.";
    }
}
