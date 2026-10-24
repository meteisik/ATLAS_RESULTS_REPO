import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P07_V1_OnyxBeacon {

    public void deleteOnyxBeaconAccount() throws SQLException {
        String data;
        data = System.getenv("ONYX_BEACON_ACCOUNT_ID");
        String requester = System.getProperty("user.name");
        boolean authorized = (new CWE284_P07_V1_OnyxBeaconChecker()).isAuthorized(requester);
        Connection onyxBeaconConnection = DriverManager.getConnection("jdbc:hsqldb:mem:onyxBeacon");
        try {
            PreparedStatement onyxBeaconDelete = onyxBeaconConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            onyxBeaconDelete.setString(1, data);
            if (authorized) {
                onyxBeaconDelete.executeUpdate();
            }
        } finally {
            onyxBeaconConnection.close();
        }
    }
}

class CWE284_P07_V1_OnyxBeaconChecker {
    public boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        boolean authorized = operator != null && operator.equals(accountId);
        return authorized;
    }
}
