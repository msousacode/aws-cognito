### Step 1: Add dependencies
```
<!-- https://mvnrepository.com/artifact/com.amazonaws/aws-java-sdk-cognitoidp -->
<dependency>
    <groupId>com.amazonaws</groupId>
    <artifactId>aws-java-sdk-cognitoidp</artifactId>
    <version>1.12.441</version>
</dependency>

<!-- https://mvnrepository.com/artifact/com.nimbusds/nimbus-jose-jwt -->
<dependency>
    <groupId>com.nimbusds</groupId>
    <artifactId>nimbus-jose-jwt</artifactId>
    <version>9.31</version>
</dependency>
```

### Step 2: Config Spring Security
```
import com.msousacode.bolao.security.filter.AwsCognitoJwtAuthFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
public class SecurityConfiguration {

    @Autowired
    private AwsCognitoJwtAuthFilter awsCognitoJwtAuthenticationFilter;

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        return http.
                csrf().disable()
                .httpBasic().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeRequests(c -> c
                    .antMatchers(
                            "/api/login",
                            "/v2/api-docs",
                            "/v3/api-docs",
                            "/configuration/ui",
                            "/swagger-resources/**",
                            "**/health",
                            "/swagger-ui/**",
                            "/webjars/**",
                            "/csrf/**").permitAll())
                .authorizeRequests()
                .anyRequest().authenticated()
                .and()
                .addFilterBefore(awsCognitoJwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .build();
    }
}
```

### Step 3: Config Cognito
```
import com.amazonaws.auth.EnvironmentVariableCredentialsProvider;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProvider;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProviderClientBuilder;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jose.util.ResourceRetriever;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Component;

import java.net.MalformedURLException;
import java.net.URL;

@Component
public class CognitoConfiguration {

    private Logger logger = LoggerFactory.getLogger(CognitoConfiguration.class);

    @Value("${aws.cognito.clientId}")
    private String clientId;

    @Value("${aws.cognito.secret}")
    private String clientSecret;

    @Value("${aws.cognito.region}")
    private String region;

    @Value("${aws.cognito.jwkUrl}")
    private String jwkUrl;

    @Bean
    public AWSCognitoIdentityProvider cognitoIdentityProvider() {
        logger.debug("Configuring Cognito");

        //Outra maneira de capturar as variáveis do Cognito, pode-se armazenar os valores no application.properties.
        //BasicAWSCredentials awsCredentials = new BasicAWSCredentials("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY");

        var awsCredentials = new EnvironmentVariableCredentialsProvider();
        AWSCognitoIdentityProvider cognitoIdentityProvider = AWSCognitoIdentityProviderClientBuilder.standard()
                .withRegion(region)
                //Aqui incorma as credenciais
                //.withCredentials(new AWSStaticCredentialsProvider(awsCredentials)).build();
                .withCredentials(awsCredentials).build();
        logger.debug("Cognito initialized successfully");
        return cognitoIdentityProvider;
    }

    @Bean
    public ConfigurableJWTProcessor configurableJWTProcessor() throws MalformedURLException {
        ResourceRetriever resourceRetriever =
                new DefaultResourceRetriever(2000, 2000);
        URL jwkURL = new URL(jwkUrl);
        JWKSource keySource = new RemoteJWKSet(jwkURL, resourceRetriever);
        ConfigurableJWTProcessor jwtProcessor = new DefaultJWTProcessor();
        JWSKeySelector keySelector = new JWSVerificationKeySelector(JWSAlgorithm.RS256, keySource);
        jwtProcessor.setJWSKeySelector(keySelector);
        return jwtProcessor;
    }
}
```

### Step 4: Create CognitoIdTokenProcessor
```
import com.msousa.cognito.security.cognito.CognitoIdTokenProcessor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

@Component
public class AwsCognitoJwtAuthFilter extends GenericFilter {

    @Autowired
    private CognitoIdTokenProcessor awsCognitoIdTokenProcessor;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain) throws IOException, ServletException {

        Authentication authentication;

        try {
            authentication = this.awsCognitoIdTokenProcessor.authenticate((HttpServletRequest) request);
            if (authentication != null) {
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        } catch (Exception var6) {
            SecurityContextHolder.clearContext();
        }

        filterChain.doFilter(request, response);
    }
}
```


### Step 5: Create JWT Authentication Token
```
import com.nimbusds.jwt.JWTClaimsSet;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class JwtAuthenticationToken extends AbstractAuthenticationToken {

    private final Object principal;
    private final JWTClaimsSet jwtClaimsSet;

    public JwtAuthenticationToken(Object principal, JWTClaimsSet jwtClaimsSet, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.principal = principal;
        this.jwtClaimsSet = jwtClaimsSet;
        super.setAuthenticated(true);
    }

    public Object getCredentials() {
        return null;
    }

    public Object getPrincipal() {
        return this.principal;
    }

    public JWTClaimsSet getJwtClaimsSet() {
        return this.jwtClaimsSet;
    }
}
```

### Step 6: Enable AwsCognitoJwtAuthenticationFilter in filter Spring Security  

```
@Autowired
private AwsCognitoJwtAuthFilter awsCognitoJwtAuthenticationFilter;

.addFilterBefore(awsCognitoJwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
```

### Step 7: Config Cognito in AWS

watch my series in youtube : https://www.youtube.com/watch?v=VdSw8S9HzNA
