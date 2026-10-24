import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P04_V2_ObsidianBeaconSafe {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    private boolean checkObsidianBeaconAccess(String accountId) {
        boolean authorized = isAuthorized(accountId);
        return authorized;
    }

    public void deleteObsidianBeaconAccount() throws SQLException {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = System.getenv("OBSIDIAN_BEACON_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = checkObsidianBeaconAccess(data);
        Connection obsidianBeaconConnection = DriverManager.getConnection("jdbc:hsqldb:mem:obsidianBeacon");
        try {
            PreparedStatement obsidianBeaconDelete = obsidianBeaconConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            obsidianBeaconDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                obsidianBeaconDelete.executeUpdate();
            }
        } finally {
            obsidianBeaconConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
