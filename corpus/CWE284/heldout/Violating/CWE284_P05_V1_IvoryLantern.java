import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P05_V1_IvoryLantern {

    private String ivoryLanternAccountId;

    private boolean ivoryLanternAuthorized;

    private void applyIvoryLanternDeletion() throws SQLException {
        String data = ivoryLanternAccountId;
        boolean authorized = ivoryLanternAuthorized;
        Connection ivoryLanternConnection = DriverManager.getConnection("jdbc:hsqldb:mem:ivoryLantern");
        try {
            PreparedStatement ivoryLanternDelete = ivoryLanternConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            ivoryLanternDelete.setString(1, data);
            ivoryLanternDelete.executeUpdate();
        } finally {
            ivoryLanternConnection.close();
        }
    }

    public void deleteIvoryLanternAccount() throws SQLException {
        String data;
        data = System.getenv("IVORY_LANTERN_ACCOUNT_ID");
        ivoryLanternAccountId = data;
        ivoryLanternAuthorized = isAuthorized(data);
        applyIvoryLanternDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
