package com.acme.clipcascade.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.session.Session;
import org.springframework.session.security.SpringSessionBackedSessionRegistry;
import com.acme.clipcascade.service.BruteForceProtectionService;
import com.acme.clipcascade.service.FacadeUserService;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

	private final UserDetailsService userDetailsService; // <- Spring Security UserDetailsService
	private final BCryptPasswordEncoder bCryptPasswordEncoder;
	private final BruteForceProtectionService bruteForceProtectionService;
	private final FacadeUserService facadeUserService;

	SecurityConfiguration(
			UserDetailsService userDetailsService,
			BCryptPasswordEncoder bCryptPasswordEncoder,
			BruteForceProtectionService bruteForceProtectionService,
			FacadeUserService facadeUserService) {

		this.userDetailsService = userDetailsService;
		this.bCryptPasswordEncoder = bCryptPasswordEncoder;
		this.bruteForceProtectionService = bruteForceProtectionService;
		this.facadeUserService = facadeUserService;
	}

	// duohub fork：使用 Spring Session 持久化的 SessionRegistry。
	// 上游用的 SessionRegistryImpl 是内存 Map，容器重启即清空所有 session，
	// 全部客户端被迫 logout + 重输密码。这里改成 SpringSessionBackedSessionRegistry，
	// 底层用 spring-session-jdbc 把 session 写到 H2 的 SPRING_SESSION 表，
	// 重启后所有 cookie 仍然有效。
	@Bean
	public SessionRegistry sessionRegistry(
			FindByIndexNameSessionRepository<? extends Session> sessionRepository) {
		return new SpringSessionBackedSessionRegistry<>(sessionRepository);
	}

	// Ensures the SessionRegistry is notified of session lifecycle events
	@Bean
	public HttpSessionEventPublisher httpSessionEventPublisher() {
		return new HttpSessionEventPublisher();
	}

	@Bean
	public SecurityFilterChain securityFilterChain(
			HttpSecurity http,
			SessionRegistry sessionRegistry) throws Exception {
		return http
				.authorizeHttpRequests((authorize) -> authorize
						.requestMatchers(
								"/login",
								"/logout",
								"/signup",
								"/captcha",
								"/help",
								"/donate",
								"/health",
								"/ping",
								"/assets/**")
						.permitAll() // <- Allow access to these URLs without authentication
						.anyRequest().authenticated()) // All other requests require authentication
				.formLogin(form -> form
						.loginPage("/login") // <- custom login URL
						.failureUrl("/login?error") // <- Where to go if login fails
						.successHandler(
								new CustomAuthenticationSuccessHandler(
										bruteForceProtectionService,
										facadeUserService))) // <- Custom authentication success handler
				.logout(logout -> logout
						.logoutUrl("/logout") // The URL to submit a logout request
						.logoutSuccessUrl("/login?logout")) // Where to go after successful logout
				.sessionManagement(session -> session
						.sessionCreationPolicy(SessionCreationPolicy.ALWAYS) // Always create a new session
						.maximumSessions(-1) // Allow unlimited sessions
						.sessionRegistry(sessionRegistry) // duohub fork：注入持久化 SessionRegistry
						.expiredSessionStrategy(new CustomExpiredSession())) // Custom expired session strategy
				.build();
	}

	@Bean
	public AuthenticationProvider authenticationProvider() {
		DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
		provider.setPasswordEncoder(bCryptPasswordEncoder);
		provider.setUserDetailsService(userDetailsService);
		return provider;
	}
}
