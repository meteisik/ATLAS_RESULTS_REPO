import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P01_V2_IvoryLanternSafe {
    private static boolean privateReturnsTrue() { return true; }

    public void deleteIvoryLanternAccount() throws SQLException {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("IVORY_LANTERN_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = isAuthorized(data);
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

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
