import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P07_V1_OnyxLanternSafe {

    public void deleteOnyxLanternAccount() throws SQLException {
        String data;
        data = System.getenv("ONYX_LANTERN_ACCOUNT_ID");
        String requester = System.getProperty("user.name");
        boolean authorized = (new CWE284_P07_V1_OnyxLanternSafeChecker()).isAuthorized(data);
        Connection onyxLanternConnection = DriverManager.getConnection("jdbc:hsqldb:mem:onyxLantern");
        try {
            PreparedStatement onyxLanternDelete = onyxLanternConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            onyxLanternDelete.setString(1, data);
            if (authorized) {
                onyxLanternDelete.executeUpdate();
            }
        } finally {
            onyxLanternConnection.close();
        }
    }
}

class CWE284_P07_V1_OnyxLanternSafeChecker {
    public boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        boolean authorized = operator != null && operator.equals(accountId);
        return authorized;
    }
}
