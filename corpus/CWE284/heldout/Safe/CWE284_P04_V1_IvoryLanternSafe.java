import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P04_V1_IvoryLanternSafe {

    private boolean checkIvoryLanternAccess(String accountId) {
        boolean authorized = isAuthorized(accountId);
        return authorized;
    }

    public void deleteIvoryLanternAccount() throws SQLException {
        String data;
        data = System.getenv("IVORY_LANTERN_ACCOUNT_ID");
        boolean authorized = checkIvoryLanternAccess(data);
        Connection ivoryLanternConnection = DriverManager.getConnection("jdbc:hsqldb:mem:ivoryLantern");
        try {
            PreparedStatement ivoryLanternDelete = ivoryLanternConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            ivoryLanternDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                ivoryLanternDelete.executeUpdate();
            }
        } finally {
            ivoryLanternConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
