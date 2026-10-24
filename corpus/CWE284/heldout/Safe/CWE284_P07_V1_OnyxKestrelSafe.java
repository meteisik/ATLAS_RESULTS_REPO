import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P07_V1_OnyxKestrelSafe {

    public void deleteOnyxKestrelAccount() throws SQLException {
        String data;
        data = System.getenv("ONYX_KESTREL_ACCOUNT_ID");
        String requester = System.getProperty("user.name");
        boolean authorized = (new CWE284_P07_V1_OnyxKestrelSafeChecker()).isAuthorized(data);
        Connection onyxKestrelConnection = DriverManager.getConnection("jdbc:hsqldb:mem:onyxKestrel");
        try {
            PreparedStatement onyxKestrelDelete = onyxKestrelConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            onyxKestrelDelete.setString(1, data);
            if (authorized) {
                onyxKestrelDelete.executeUpdate();
            }
        } finally {
            onyxKestrelConnection.close();
        }
    }
}

class CWE284_P07_V1_OnyxKestrelSafeChecker {
    public boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        boolean authorized = operator != null && operator.equals(accountId);
        return authorized;
    }
}
