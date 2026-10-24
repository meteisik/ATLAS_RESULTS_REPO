import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P03_V2_ObsidianBeacon {

    private void applyObsidianBeaconDeletion(String data, boolean authorized) throws SQLException {
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
        if (true) {
            data = System.getenv("OBSIDIAN_BEACON_ACCOUNT_ID");
        } else {
            data = null;
        }
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(requester);
        applyObsidianBeaconDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
