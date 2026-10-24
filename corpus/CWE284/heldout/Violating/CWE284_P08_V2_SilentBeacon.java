import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P08_V2_SilentBeacon {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public void deleteSilentBeaconAccount() throws SQLException {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("SILENT_BEACON_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean[] decisions = new boolean[5];
        decisions[2] = isAuthorized(data);
        (new CWE284_P08_V2_SilentBeaconSink()).applySilentBeaconDeletion(data, decisions);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P08_V2_SilentBeaconSink {
    public void applySilentBeaconDeletion(String data, boolean[] decisions) throws SQLException {
        boolean authorized = decisions[2];
        Connection silentBeaconConnection = DriverManager.getConnection("jdbc:hsqldb:mem:silentBeacon");
        try {
            PreparedStatement silentBeaconDelete = silentBeaconConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            silentBeaconDelete.setString(1, data);
            if (authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                silentBeaconDelete.executeUpdate();
            }
        } finally {
            silentBeaconConnection.close();
        }
    }
}
