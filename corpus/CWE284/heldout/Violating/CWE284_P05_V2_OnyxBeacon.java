import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P05_V2_OnyxBeacon {

    private String onyxBeaconAccountId;

    private boolean onyxBeaconAuthorized;

    private void applyOnyxBeaconDeletion() throws SQLException {
        String data = onyxBeaconAccountId;
        boolean authorized = onyxBeaconAuthorized;
        Connection onyxBeaconConnection = DriverManager.getConnection("jdbc:hsqldb:mem:onyxBeacon");
        try {
            PreparedStatement onyxBeaconDelete = onyxBeaconConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            onyxBeaconDelete.setString(1, data);
            onyxBeaconDelete.executeUpdate();
        } finally {
            onyxBeaconConnection.close();
        }
    }

    public void deleteOnyxBeaconAccount() throws SQLException {
        String data;
        data = null;
        for (int j = 0; j < 1; j++) {
            data = System.getenv("ONYX_BEACON_ACCOUNT_ID");
        }
        onyxBeaconAccountId = data;
        onyxBeaconAuthorized = isAuthorized(data);
        applyOnyxBeaconDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
