import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P05_V1_IvoryRavenSafe {

    private String ivoryRavenAccountId;

    private boolean ivoryRavenAuthorized;

    private void applyIvoryRavenDeletion() throws SQLException {
        String data = ivoryRavenAccountId;
        boolean authorized = ivoryRavenAuthorized;
        Connection ivoryRavenConnection = DriverManager.getConnection("jdbc:hsqldb:mem:ivoryRaven");
        try {
            PreparedStatement ivoryRavenDelete = ivoryRavenConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            ivoryRavenDelete.setString(1, data);
            if (authorized) {
                ivoryRavenDelete.executeUpdate();
            }
        } finally {
            ivoryRavenConnection.close();
        }
    }

    public void deleteIvoryRavenAccount() throws SQLException {
        String data;
        data = System.getenv("IVORY_RAVEN_ACCOUNT_ID");
        ivoryRavenAccountId = data;
        ivoryRavenAuthorized = isAuthorized(data);
        applyIvoryRavenDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
