import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P03_V1_IvoryBeacon {

    private void applyIvoryBeaconDeletion(String data, boolean authorized) throws SQLException {
        Connection ivoryBeaconConnection = DriverManager.getConnection("jdbc:hsqldb:mem:ivoryBeacon");
        try {
            PreparedStatement ivoryBeaconDelete = ivoryBeaconConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            ivoryBeaconDelete.setString(1, data);
            if (authorized) {
                ivoryBeaconDelete.executeUpdate();
            }
        } finally {
            ivoryBeaconConnection.close();
        }
    }

    public void deleteIvoryBeaconAccount() throws SQLException {
        String data;
        data = System.getenv("IVORY_BEACON_ACCOUNT_ID");
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(requester);
        applyIvoryBeaconDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
