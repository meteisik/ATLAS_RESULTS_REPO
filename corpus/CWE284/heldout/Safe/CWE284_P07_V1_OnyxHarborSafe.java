import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P07_V1_OnyxHarborSafe {

    public void deleteOnyxHarborAccount() throws SQLException {
        String data;
        data = System.getenv("ONYX_HARBOR_ACCOUNT_ID");
        String requester = System.getProperty("user.name");
        boolean authorized = (new CWE284_P07_V1_OnyxHarborSafeChecker()).isAuthorized(data);
        Connection onyxHarborConnection = DriverManager.getConnection("jdbc:hsqldb:mem:onyxHarbor");
        try {
            PreparedStatement onyxHarborDelete = onyxHarborConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            onyxHarborDelete.setString(1, data);
            if (authorized) {
                onyxHarborDelete.executeUpdate();
            }
        } finally {
            onyxHarborConnection.close();
        }
    }
}

class CWE284_P07_V1_OnyxHarborSafeChecker {
    public boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        boolean authorized = operator != null && operator.equals(accountId);
        return authorized;
    }
}
