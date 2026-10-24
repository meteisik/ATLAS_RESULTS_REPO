import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P05_V2_ObsidianBeaconSafe {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    private String obsidianBeaconAccountId;

    private boolean obsidianBeaconAuthorized;

    private void applyObsidianBeaconDeletion() throws SQLException {
        String data = obsidianBeaconAccountId;
        boolean authorized = obsidianBeaconAuthorized;
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

    public void deleteObsidianBeaconAccount() throws SQLException {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("OBSIDIAN_BEACON_ACCOUNT_ID");
        } else {
            data = null;
        }
        obsidianBeaconAccountId = data;
        obsidianBeaconAuthorized = isAuthorized(data);
        applyObsidianBeaconDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
