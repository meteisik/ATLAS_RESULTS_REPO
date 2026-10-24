import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P06_V1_ObsidianBeaconSafe {

    public void deleteObsidianBeaconAccount() throws SQLException {
        String data;
        data = System.getenv("OBSIDIAN_BEACON_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        (new CWE284_P06_V1_ObsidianBeaconSafeSink()).applyObsidianBeaconDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P06_V1_ObsidianBeaconSafeSink {
    public void applyObsidianBeaconDeletion(String data, boolean authorized) throws SQLException {
        Connection obsidianBeaconConnection = DriverManager.getConnection("jdbc:hsqldb:mem:obsidianBeacon");
        try {
            PreparedStatement obsidianBeaconDelete = obsidianBeaconConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            obsidianBeaconDelete.setString(1, data);
            if (authorized) {
                obsidianBeaconDelete.executeUpdate();
            } else {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            obsidianBeaconConnection.close();
        }
    }
}
