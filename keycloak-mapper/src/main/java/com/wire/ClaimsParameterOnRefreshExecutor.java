package com.wire;

import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.representations.ClaimsRepresentation;
import org.keycloak.representations.idm.ClientPolicyExecutorConfigurationRepresentation;
import org.keycloak.services.clientpolicy.ClientPolicyContext;
import org.keycloak.services.clientpolicy.context.TokenRefreshResponseContext;
import org.keycloak.services.clientpolicy.executor.ClientPolicyExecutorProvider;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;
import java.util.List;
import java.util.Map;

/**
 * This helps in the context of E2EI to renew an IdToken from a RefreshToken and to update the "keyauth" & "acme_aud" claims
 * which are dependent from the ACME client account keypair and the ACME challenge token.
 * This is equivalent to {@link org.keycloak.protocol.oidc.mappers.ClaimsParameterWithValueIdTokenMapper} but for the
 * {@link org.keycloak.protocol.oidc.endpoints.TokenEndpoint} instead of the {@link org.keycloak.protocol.oidc.endpoints.AuthorizationEndpoint}
 */
public class ClaimsParameterOnRefreshExecutor implements ClientPolicyExecutorProvider<ClientPolicyExecutorConfigurationRepresentation> {

    private static final Logger logger = Logger.getLogger(ClaimsParameterOnRefreshExecutor.class);

    protected final KeycloakSession session;

    public ClaimsParameterOnRefreshExecutor(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public String getProviderId() {
        return ClaimsParameterOnRefreshExecutorFactory.PROVIDER_ID;
    }

    @Override
    public void executeOnEvent(ClientPolicyContext context) {
        switch (context.getEvent()) {
            case TOKEN_REFRESH_RESPONSE:
                TokenRefreshResponseContext tokenRefreshResponseContext = (TokenRefreshResponseContext) context;

                Map.Entry<String, List<String>> maybeRefreshClaimsList = tokenRefreshResponseContext.getParams()
                        .entrySet().stream()
                        .filter(e -> "claims".equals(e.getKey()))
                        .findFirst()
                        .orElse(null);

                if (maybeRefreshClaimsList == null) {
                    return;
                }
                String refreshClaims = maybeRefreshClaimsList.getValue().stream().findFirst().orElse(null);
                if (refreshClaims == null) {
                    return;
                }

                ClaimsRepresentation claimsRep;
                try {
                    claimsRep = JsonSerialization.readValue(refreshClaims, ClaimsRepresentation.class);
                } catch (IOException e) {
                    logger.warn("Invalid extra claims supplied");
                    return;
                }

                TokenManager.AccessTokenResponseBuilder builder = tokenRefreshResponseContext.getAccessTokenResponseBuilder();
                claimsRep.getIdTokenClaims().entrySet().stream()
                        .filter(e -> "keyauth".equals(e.getKey()) || "acme_aud".equals(e.getKey()))
                        .forEach(e -> builder.getIdToken().setOtherClaims(e.getKey(), e.getValue().getValue()));
                break;
            default:
        }
    }
}
