package com.localega.tsdproxywebservice;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.web.PortMapperImpl;
import org.springframework.security.web.PortResolverImpl;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.web.client.RestTemplate;

import java.util.Collections;

@Slf4j
@EnableCaching
@SpringBootApplication
public class TsdProxyWebserviceApplication extends WebSecurityConfigurerAdapter {

    public static void main(String[] args) {
        SpringApplication.run(TsdProxyWebserviceApplication.class, args);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        PortMapperImpl portMapper = new PortMapperImpl();
        portMapper.setPortMappings(Collections.singletonMap("8080", "8080"));
        PortResolverImpl portResolver = new PortResolverImpl();
        portResolver.setPortMapper(portMapper);
        LoginUrlAuthenticationEntryPoint entryPoint = new LoginUrlAuthenticationEntryPoint("/oauth2/authorization/elixir-aai");
        entryPoint.setPortMapper(portMapper);
        entryPoint.setPortResolver(portResolver);
        http
                .requiresChannel()
                .anyRequest().requiresSecure()
                .and()
                .exceptionHandling()
                .authenticationEntryPoint(entryPoint)
                .and()
                .csrf().disable()
                .authorizeRequests()
                .mvcMatchers("/token.html").authenticated()
                .mvcMatchers("/token").authenticated()
                .mvcMatchers("/user").authenticated()
                .and()
                .oauth2Login()
                .redirectionEndpoint().baseUri("/oidc-protected")
                .and()
                .defaultSuccessUrl("/");
    }

    @Bean
    public ClientRegistrationRepository clientRegistrationRepository(@Value("${elixir.client.id}") String elixirAAIClientId,
                                                                     @Value("${elixir.client.secret}") String elixirAAIClientSecret
    ) {
        return new InMemoryClientRegistrationRepository(
                ClientRegistration.withRegistrationId("elixir-aai")
                        .clientId(elixirAAIClientId)
                        .clientSecret(elixirAAIClientSecret)
                        .clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
                        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                        .redirectUriTemplate("{baseUrl}/oidc-protected")
                        .scope("openid", "ga4gh_passport_v1")
                        .authorizationUri("https://login.elixir-czech.org/oidc/authorize")
                        .tokenUri("https://login.elixir-czech.org/oidc/token")
                        .userInfoUri("https://login.elixir-czech.org/oidc/userinfo")
                        .userNameAttributeName(IdTokenClaimNames.SUB)
                        .jwkSetUri("https://login.elixir-czech.org/oidc/jwk")
                        .clientName("elixir-aai")
                        .build()
        );
    }

    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }
}
