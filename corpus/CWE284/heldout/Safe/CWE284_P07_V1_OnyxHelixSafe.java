import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P07_V1_OnyxHelixSafe {

    public void deleteOnyxHelixAccount() throws SQLException {
        String data;
        data = System.getenv("ONYX_HELIX_ACCOUNT_ID");
        String requester = System.getProperty("user.name");
        boolean authorized = (new CWE284_P07_V1_OnyxHelixSafeChecker()).isAuthorized(data);
        Connection onyxHelixConnection = DriverManager.getConnection("jdbc:hsqldb:mem:onyxHelix");
        try {
            PreparedStatement onyxHelixDelete = onyxHelixConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            onyxHelixDelete.setString(1, data);
            if (authorized) {
                onyxHelixDelete.executeUpdate();
            }
        } finally {
            onyxHelixConnection.close();
        }
    }
}

class CWE284_P07_V1_OnyxHelixSafeChecker {
    public boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        boolean authorized = operator != null && operator.equals(accountId);
        return authorized;
    }
}
