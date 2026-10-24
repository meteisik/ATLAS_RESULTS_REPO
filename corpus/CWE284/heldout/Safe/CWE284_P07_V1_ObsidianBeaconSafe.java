import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P07_V1_ObsidianBeaconSafe {

    public void deleteObsidianBeaconAccount() throws SQLException {
        String data;
        data = System.getenv("OBSIDIAN_BEACON_ACCOUNT_ID");
        String requester = System.getProperty("user.name");
        boolean authorized = (new CWE284_P07_V1_ObsidianBeaconSafeChecker()).isAuthorized(data);
        Connection obsidianBeaconConnection = DriverManager.getConnection("jdbc:hsqldb:mem:obsidianBeacon");
        try {
            PreparedStatement obsidianBeaconDelete = obsidianBeaconConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            obsidianBeaconDelete.setString(1, data);
            if (authorized) {
                obsidianBeaconDelete.executeUpdate();
            }
        } finally {
            obsidianBeaconConnection.close();
        }
    }
}

class CWE284_P07_V1_ObsidianBeaconSafeChecker {
    public boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        boolean authorized = operator != null && operator.equals(accountId);
        return authorized;
    }
}
