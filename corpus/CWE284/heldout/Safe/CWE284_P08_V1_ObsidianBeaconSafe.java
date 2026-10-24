import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P08_V1_ObsidianBeaconSafe {

    public void deleteObsidianBeaconAccount() throws SQLException {
        String data;
        data = System.getenv("OBSIDIAN_BEACON_ACCOUNT_ID");
        boolean[] decisions = new boolean[5];
        decisions[2] = isAuthorized(data);
        (new CWE284_P08_V1_ObsidianBeaconSafeSink()).applyObsidianBeaconDeletion(data, decisions);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P08_V1_ObsidianBeaconSafeSink {
    public void applyObsidianBeaconDeletion(String data, boolean[] decisions) throws SQLException {
        boolean authorized = decisions[2];
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
}
