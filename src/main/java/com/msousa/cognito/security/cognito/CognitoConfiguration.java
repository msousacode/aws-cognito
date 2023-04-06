package com.msousa.cognito.security.cognito;

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
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Component;

import java.net.MalformedURLException;
import java.net.URL;

@Component
public class CognitoConfiguration {

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

        var awsCredentials = new EnvironmentVariableCredentialsProvider();
        AWSCognitoIdentityProvider cognitoIdentityProvider = AWSCognitoIdentityProviderClientBuilder.standard()
                .withRegion(region)
                //Aqui informa as credenciais
                //.withCredentials(new AWSStaticCredentialsProvider(awsCredentials)).build();
                .withCredentials(awsCredentials).build();
        return cognitoIdentityProvider;
    }

    @Bean
    public ConfigurableJWTProcessor configurableJWTProcessor() throws MalformedURLException {
        ResourceRetriever resourceRetriever = new DefaultResourceRetriever(2000, 2000);
        URL jwkURL = new URL(jwkUrl);
        JWKSource keySource = new RemoteJWKSet(jwkURL, resourceRetriever);
        ConfigurableJWTProcessor jwtProcessor = new DefaultJWTProcessor();
        JWSKeySelector keySelector = new JWSVerificationKeySelector(JWSAlgorithm.RS256, keySource);
        jwtProcessor.setJWSKeySelector(keySelector);
        return jwtProcessor;
    }
}
