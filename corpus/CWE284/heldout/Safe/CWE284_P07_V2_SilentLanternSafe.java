import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P07_V2_SilentLanternSafe {
    private static int privateFive = 5;

    public void deleteSilentLanternAccount() throws SQLException {
        String data;
        if (privateFive == 5) {
            data = System.getenv("SILENT_LANTERN_ACCOUNT_ID");
        } else {
            data = null;
        }
        String requester = System.getProperty("user.name");
        boolean authorized = (new CWE284_P07_V2_SilentLanternSafeChecker()).isAuthorized(data);
        Connection silentLanternConnection = DriverManager.getConnection("jdbc:hsqldb:mem:silentLantern");
        try {
            PreparedStatement silentLanternDelete = silentLanternConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            silentLanternDelete.setString(1, data);
            if (authorized) {
                silentLanternDelete.executeUpdate();
            }
        } finally {
            silentLanternConnection.close();
        }
    }
}

class CWE284_P07_V2_SilentLanternSafeChecker {
    public boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        boolean authorized = operator != null && operator.equals(accountId);
        return authorized;
    }
}
