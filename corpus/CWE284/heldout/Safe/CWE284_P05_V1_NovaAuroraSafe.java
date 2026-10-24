import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P05_V1_NovaAuroraSafe {

    private String novaAuroraAccountId;

    private boolean novaAuroraAuthorized;

    private void applyNovaAuroraDeletion() throws SQLException {
        String data = novaAuroraAccountId;
        boolean authorized = novaAuroraAuthorized;
        Connection novaAuroraConnection = DriverManager.getConnection("jdbc:hsqldb:mem:novaAurora");
        try {
            PreparedStatement novaAuroraDelete = novaAuroraConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            novaAuroraDelete.setString(1, data);
            if (authorized) {
                novaAuroraDelete.executeUpdate();
            }
        } finally {
            novaAuroraConnection.close();
        }
    }

    public void deleteNovaAuroraAccount() throws SQLException {
        String data;
        data = System.getenv("NOVA_AURORA_ACCOUNT_ID");
        novaAuroraAccountId = data;
        novaAuroraAuthorized = isAuthorized(data);
        applyNovaAuroraDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
