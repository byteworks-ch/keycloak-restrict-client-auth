package de.sventorben.keycloak.authorization.client.access.userAttribute;

import de.sventorben.keycloak.authorization.client.access.AccessProvider;
import org.jboss.logging.Logger;
import org.keycloak.models.ClientModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;

public final class UserAttributeBasedAccessProvider implements AccessProvider {

    private static final Logger LOG = Logger.getLogger(UserAttributeBasedAccessProvider.class);

    private final String clientRoleName;
    private final String userAttributeName;

    UserAttributeBasedAccessProvider(String clientRoleName, String userAttributeName) {
        this.clientRoleName = clientRoleName;
        this.userAttributeName = userAttributeName;
    }

    @Override
    public boolean isRestricted(ClientModel client) {
        return client.getRole(clientRoleName) != null;
    }

    @Override
    public boolean isPermitted(ClientModel client, UserModel user) {
        if (client == null) return false;
        if (user == null) return false;

        String clientId = client.getClientId();
        boolean permitted = user.getAttributeStream(userAttributeName).anyMatch(a -> a.equals(clientId));
        if (permitted) {
            LOG.debugf(
                "Access for user '%s' to client '%s' in realm '%s' granted.",
                user.getUsername(), client.getClientId(), client.getRealm().getName());
        } else {
            LOG.warnf("Access for user '%s' to client '%s' in realm '%s' is denied. User does not have value '%s' in attribute '%s'.",
                    user.getUsername(), client.getClientId(), client.getRealm().getName(), clientId, userAttributeName);
        }
        return permitted;
    }

    @Override
    public void enableFor(ClientModel client) {
        if (isRestricted(client)) return;
        client.addRole(clientRoleName);
    }

    @Override
    public void close() {
    }
}
