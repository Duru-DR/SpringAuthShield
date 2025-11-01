package com.duru.authentication.security.oauth2;

import com.duru.authentication.model.*;
import com.duru.authentication.model.enums.Status;
import com.duru.authentication.repository.UserRepository;
import com.duru.authentication.util.TokenUtil;
import jakarta.servlet.http.*;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.util.*;

@Component
@RequiredArgsConstructor
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private final UserRepository userRepository;
    private final TokenUtil tokenUtil;

    @Override
    @Transactional
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws IOException {
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();

        String email = oAuth2User.getAttribute("email");
        String fullName = oAuth2User.getAttribute("name");

        User user = userRepository.findByEmail(email).orElseGet(() -> {
            User newUser = User.builder()
                    .email(email)
                    .username(email.split("@")[0])
                    .password(UUID.randomUUID().toString())
                    .fullName(fullName)
                    .enabled(true)
                    .status(Status.ACTIVE)
                    .auditInfo(new AuditInfo())
                    .build();
            return userRepository.save(newUser);
        });

        Collection<String> roles = Optional.ofNullable(user.getRoles())
                .orElse(Collections.emptySet())
                .stream()
                .map(Role::getName)
                .toList();

        String accessToken = tokenUtil.generateAndAttachTokens(user, roles, response);

        response.setContentType("application/json");
        response.getWriter().write("{\"accessToken\": \"" + accessToken + "\"}");
    }
}
