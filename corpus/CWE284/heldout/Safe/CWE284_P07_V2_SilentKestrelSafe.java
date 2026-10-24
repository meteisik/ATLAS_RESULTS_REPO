import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P07_V2_SilentKestrelSafe {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public void deleteSilentKestrelAccount() throws SQLException {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("SILENT_KESTREL_ACCOUNT_ID");
        } else {
            data = null;
        }
        String requester = System.getProperty("user.name");
        boolean authorized = (new CWE284_P07_V2_SilentKestrelSafeChecker()).isAuthorized(data);
        Connection silentKestrelConnection = DriverManager.getConnection("jdbc:hsqldb:mem:silentKestrel");
        try {
            PreparedStatement silentKestrelDelete = silentKestrelConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            silentKestrelDelete.setString(1, data);
            if (authorized) {
                silentKestrelDelete.executeUpdate();
            }
        } finally {
            silentKestrelConnection.close();
        }
    }
}

class CWE284_P07_V2_SilentKestrelSafeChecker {
    public boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        boolean authorized = operator != null && operator.equals(accountId);
        return authorized;
    }
}
