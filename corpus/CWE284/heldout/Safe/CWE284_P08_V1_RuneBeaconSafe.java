import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P08_V1_RuneBeaconSafe {

    public void deleteRuneBeaconAccount() throws SQLException {
        String data;
        data = System.getenv("RUNE_BEACON_ACCOUNT_ID");
        boolean[] decisions = new boolean[5];
        decisions[2] = isAuthorized(data);
        (new CWE284_P08_V1_RuneBeaconSafeSink()).applyRuneBeaconDeletion(data, decisions);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P08_V1_RuneBeaconSafeSink {
    public void applyRuneBeaconDeletion(String data, boolean[] decisions) throws SQLException {
        boolean authorized = decisions[2];
        Connection runeBeaconConnection = DriverManager.getConnection("jdbc:hsqldb:mem:runeBeacon");
        try {
            PreparedStatement runeBeaconDelete = runeBeaconConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            runeBeaconDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                runeBeaconDelete.executeUpdate();
            }
        } finally {
            runeBeaconConnection.close();
        }
    }
}
