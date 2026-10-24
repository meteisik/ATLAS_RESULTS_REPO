import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P03_V1_IvoryRaven {

    private void applyIvoryRavenDeletion(String data, boolean authorized) throws SQLException {
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
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(requester);
        applyIvoryRavenDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
