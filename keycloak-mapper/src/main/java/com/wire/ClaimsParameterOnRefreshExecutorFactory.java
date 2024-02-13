package com.wire;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.services.clientpolicy.executor.ClientPolicyExecutorProvider;
import org.keycloak.services.clientpolicy.executor.ClientPolicyExecutorProviderFactory;

import java.util.Collections;
import java.util.List;

public class ClaimsParameterOnRefreshExecutorFactory implements ClientPolicyExecutorProviderFactory {

    public static final String PROVIDER_ID = "wire-e2ei-claims-refresh";

    @Override
    public int order() {
        return 0;
    }

    @Override
    public ClientPolicyExecutorProvider create(KeycloakSession keycloakSession) {
        return new ClaimsParameterOnRefreshExecutor(keycloakSession);
    }

    @Override
    public void init(Config.Scope scope) {
    }

    @Override
    public void postInit(KeycloakSessionFactory keycloakSessionFactory) {
    }

    @Override
    public void close() {
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getHelpText() {
        return "TODO";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return Collections.emptyList();
    }

    @Override
    public boolean isSupported() {
        return true;
    }
}
