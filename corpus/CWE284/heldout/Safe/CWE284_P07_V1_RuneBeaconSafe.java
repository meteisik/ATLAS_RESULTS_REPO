import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P07_V1_RuneBeaconSafe {

    public void deleteRuneBeaconAccount() throws SQLException {
        String data;
        data = System.getenv("RUNE_BEACON_ACCOUNT_ID");
        String requester = System.getProperty("user.name");
        boolean authorized = (new CWE284_P07_V1_RuneBeaconSafeChecker()).isAuthorized(data);
        Connection runeBeaconConnection = DriverManager.getConnection("jdbc:hsqldb:mem:runeBeacon");
        try {
            PreparedStatement runeBeaconDelete = runeBeaconConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            runeBeaconDelete.setString(1, data);
            if (authorized) {
                runeBeaconDelete.executeUpdate();
            }
        } finally {
            runeBeaconConnection.close();
        }
    }
}

class CWE284_P07_V1_RuneBeaconSafeChecker {
    public boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        boolean authorized = operator != null && operator.equals(accountId);
        return authorized;
    }
}
