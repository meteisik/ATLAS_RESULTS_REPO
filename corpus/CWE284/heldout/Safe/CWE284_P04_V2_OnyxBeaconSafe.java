import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P04_V2_OnyxBeaconSafe {

    private boolean checkOnyxBeaconAccess(String accountId) {
        boolean authorized = isAuthorized(accountId);
        return authorized;
    }

    public void deleteOnyxBeaconAccount() throws SQLException {
        String data;
        switch (7) {
        case 7:
            data = System.getenv("ONYX_BEACON_ACCOUNT_ID");
            break;
        default:
            data = null;
            break;
        }
        boolean authorized = checkOnyxBeaconAccess(data);
        Connection onyxBeaconConnection = DriverManager.getConnection("jdbc:hsqldb:mem:onyxBeacon");
        try {
            PreparedStatement onyxBeaconDelete = onyxBeaconConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            onyxBeaconDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                onyxBeaconDelete.executeUpdate();
            }
        } finally {
            onyxBeaconConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
