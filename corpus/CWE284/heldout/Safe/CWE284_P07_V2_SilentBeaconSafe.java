import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P07_V2_SilentBeaconSafe {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public void deleteSilentBeaconAccount() throws SQLException {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = System.getenv("SILENT_BEACON_ACCOUNT_ID");
        } else {
            data = null;
        }
        String requester = System.getProperty("user.name");
        boolean authorized = (new CWE284_P07_V2_SilentBeaconSafeChecker()).isAuthorized(data);
        Connection silentBeaconConnection = DriverManager.getConnection("jdbc:hsqldb:mem:silentBeacon");
        try {
            PreparedStatement silentBeaconDelete = silentBeaconConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            silentBeaconDelete.setString(1, data);
            if (authorized) {
                silentBeaconDelete.executeUpdate();
            }
        } finally {
            silentBeaconConnection.close();
        }
    }
}

class CWE284_P07_V2_SilentBeaconSafeChecker {
    public boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        boolean authorized = operator != null && operator.equals(accountId);
        return authorized;
    }
}
