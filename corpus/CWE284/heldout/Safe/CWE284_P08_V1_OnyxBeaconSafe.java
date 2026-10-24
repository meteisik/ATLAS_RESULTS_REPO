import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P08_V1_OnyxBeaconSafe {

    public void deleteOnyxBeaconAccount() throws SQLException {
        String data;
        data = System.getenv("ONYX_BEACON_ACCOUNT_ID");
        boolean[] decisions = new boolean[5];
        decisions[2] = isAuthorized(data);
        (new CWE284_P08_V1_OnyxBeaconSafeSink()).applyOnyxBeaconDeletion(data, decisions);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P08_V1_OnyxBeaconSafeSink {
    public void applyOnyxBeaconDeletion(String data, boolean[] decisions) throws SQLException {
        boolean authorized = decisions[2];
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
}
