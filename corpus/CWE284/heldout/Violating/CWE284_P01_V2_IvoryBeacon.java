import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P01_V2_IvoryBeacon {

    public void deleteIvoryBeaconAccount() throws SQLException {
        String data;
        if (5 == 5) {
            data = System.getenv("IVORY_BEACON_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = isAuthorized(data);
        Connection ivoryBeaconConnection = DriverManager.getConnection("jdbc:hsqldb:mem:ivoryBeacon");
        try {
            PreparedStatement ivoryBeaconDelete = ivoryBeaconConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            ivoryBeaconDelete.setString(1, data);
            ivoryBeaconDelete.executeUpdate();
        } finally {
            ivoryBeaconConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
