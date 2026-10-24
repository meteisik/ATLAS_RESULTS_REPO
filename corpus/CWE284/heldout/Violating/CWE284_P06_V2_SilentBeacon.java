import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P06_V2_SilentBeacon {

    public void deleteSilentBeaconAccount() throws SQLException {
        String data;
        if (true) {
            data = System.getenv("SILENT_BEACON_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = isAuthorized(data);
        (new CWE284_P06_V2_SilentBeaconSink()).applySilentBeaconDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P06_V2_SilentBeaconSink {
    public void applySilentBeaconDeletion(String data, boolean authorized) throws SQLException {
        Connection silentBeaconConnection = DriverManager.getConnection("jdbc:hsqldb:mem:silentBeacon");
        try {
            PreparedStatement silentBeaconDelete = silentBeaconConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            silentBeaconDelete.setString(1, data);
            silentBeaconDelete.executeUpdate();
            if (!authorized) {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            silentBeaconConnection.close();
        }
    }
}
