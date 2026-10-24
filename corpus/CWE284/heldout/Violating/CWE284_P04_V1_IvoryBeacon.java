import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P04_V1_IvoryBeacon {

    private boolean checkIvoryBeaconAccess(String accountId) {
        boolean authorized = isAuthorized(accountId);
        return authorized;
    }

    public void deleteIvoryBeaconAccount() throws SQLException {
        String data;
        data = System.getenv("IVORY_BEACON_ACCOUNT_ID");
        boolean authorized = checkIvoryBeaconAccess(data);
        Connection ivoryBeaconConnection = DriverManager.getConnection("jdbc:hsqldb:mem:ivoryBeacon");
        try {
            PreparedStatement ivoryBeaconDelete = ivoryBeaconConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            ivoryBeaconDelete.setString(1, data);
            if (authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                ivoryBeaconDelete.executeUpdate();
            }
        } finally {
            ivoryBeaconConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
