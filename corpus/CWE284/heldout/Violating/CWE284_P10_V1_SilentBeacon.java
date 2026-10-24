import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P10_V1_SilentBeacon {

    public static String data;

    public static boolean authorized;

    public void deleteSilentBeaconAccount() throws SQLException {
        data = System.getenv("SILENT_BEACON_ACCOUNT_ID");
        authorized = isAuthorized(data);
        (new CWE284_P10_V1_SilentBeaconSink()).applySilentBeaconDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P10_V1_SilentBeaconSink {
    public void applySilentBeaconDeletion() throws SQLException {
        String data = CWE284_P10_V1_SilentBeacon.data;
        boolean authorized = CWE284_P10_V1_SilentBeacon.authorized;
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
