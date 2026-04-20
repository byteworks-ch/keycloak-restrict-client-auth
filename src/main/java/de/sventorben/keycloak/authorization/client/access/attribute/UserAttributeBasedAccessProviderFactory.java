package de.sventorben.keycloak.authorization.client.access.userAttribute;

import de.sventorben.keycloak.authorization.client.access.AccessProvider;
import de.sventorben.keycloak.authorization.client.access.AccessProviderFactory;
import de.sventorben.keycloak.authorization.client.common.OperationalInfo;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.provider.ServerInfoAwareProviderFactory;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.keycloak.provider.ProviderConfigProperty.STRING_TYPE;

public final class UserAttributeBasedAccessProviderFactory implements AccessProviderFactory, ServerInfoAwareProviderFactory {

    public static final String PROVIDER_ID = "user-attribute";

    private static final String CLIENT_ROLE_NAME = "clientRoleName";
    private static final String CLIENT_ROLE_NAME_DEFAULT = "restricted-access";

    private static final String USER_ATTRIBUTE_NAME = "userAttributeName";
    private static final String USER_ATTRIBUTE_NAME_DEFAULT = "allowedClients";

    private Config.Scope config;

    @Override
    public AccessProvider create(KeycloakSession session) {
        String clientRoleName = getClientRoleName();
        String userAttributeName = getUserAttributeName();
        return new UserAttributeBasedAccessProvider(clientRoleName, userAttributeName);
    }

    @Override
    public void init(Config.Scope config) {
        this.config = config;
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public void close() {
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public Map<String, String> getOperationalInfo() {
        Map<String, String> operationalInfo = new HashMap<>(OperationalInfo.get());
        operationalInfo.put(CLIENT_ROLE_NAME, getClientRoleName());
        operationalInfo.put(USER_ATTRIBUTE_NAME, getUserAttributeName());
        return operationalInfo;
    }

    @Override
    public List<ProviderConfigProperty> getConfigMetadata() {
        return ProviderConfigurationBuilder.create()
            .property()
            .name(CLIENT_ROLE_NAME)
            .label("Client role name")
            .defaultValue(CLIENT_ROLE_NAME_DEFAULT)
            .helpText("The name of the client role used to enable the authenticator and grant access.")
            .type(STRING_TYPE)
            .add()
            .property()
            .name(USER_ATTRIBUTE_NAME)
            .label("User attribute name")
            .defaultValue(USER_ATTRIBUTE_NAME_DEFAULT)
            .helpText("The name of the user attribute used to check for the client name and grant access.")
            .type(STRING_TYPE)
            .add()
            .build();
    }

    private String getClientRoleName() {
        return config.get(CLIENT_ROLE_NAME, CLIENT_ROLE_NAME_DEFAULT);
    }

    private String getUserAttributeName() {
        return config.get(USER_ATTRIBUTE_NAME, USER_ATTRIBUTE_NAME_DEFAULT);
    }
}
