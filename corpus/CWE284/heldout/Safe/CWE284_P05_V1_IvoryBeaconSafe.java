import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P05_V1_IvoryBeaconSafe {

    private String ivoryBeaconAccountId;

    private boolean ivoryBeaconAuthorized;

    private void applyIvoryBeaconDeletion() throws SQLException {
        String data = ivoryBeaconAccountId;
        boolean authorized = ivoryBeaconAuthorized;
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
        ivoryBeaconAccountId = data;
        ivoryBeaconAuthorized = isAuthorized(data);
        applyIvoryBeaconDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
