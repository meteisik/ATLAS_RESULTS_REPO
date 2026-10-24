import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P03_V1_IvoryLantern {

    private void applyIvoryLanternDeletion(String data, boolean authorized) throws SQLException {
        Connection ivoryLanternConnection = DriverManager.getConnection("jdbc:hsqldb:mem:ivoryLantern");
        try {
            PreparedStatement ivoryLanternDelete = ivoryLanternConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            ivoryLanternDelete.setString(1, data);
            if (authorized) {
                ivoryLanternDelete.executeUpdate();
            }
        } finally {
            ivoryLanternConnection.close();
        }
    }

    public void deleteIvoryLanternAccount() throws SQLException {
        String data;
        data = System.getenv("IVORY_LANTERN_ACCOUNT_ID");
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(requester);
        applyIvoryLanternDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
