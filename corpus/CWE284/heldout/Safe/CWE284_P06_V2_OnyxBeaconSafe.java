import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P06_V2_OnyxBeaconSafe {

    public void deleteOnyxBeaconAccount() throws SQLException {
        String data;
        if (5 == 5) {
            data = System.getenv("ONYX_BEACON_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = isAuthorized(data);
        (new CWE284_P06_V2_OnyxBeaconSafeSink()).applyOnyxBeaconDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P06_V2_OnyxBeaconSafeSink {
    public void applyOnyxBeaconDeletion(String data, boolean authorized) throws SQLException {
        Connection onyxBeaconConnection = DriverManager.getConnection("jdbc:hsqldb:mem:onyxBeacon");
        try {
            PreparedStatement onyxBeaconDelete = onyxBeaconConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            onyxBeaconDelete.setString(1, data);
            if (authorized) {
                onyxBeaconDelete.executeUpdate();
            } else {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            onyxBeaconConnection.close();
        }
    }
}
