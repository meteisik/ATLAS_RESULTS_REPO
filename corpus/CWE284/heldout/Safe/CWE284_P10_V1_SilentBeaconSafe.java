import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P10_V1_SilentBeaconSafe {

    public static String data;

    public static boolean authorized;

    public void deleteSilentBeaconAccount() throws SQLException {
        data = System.getenv("SILENT_BEACON_ACCOUNT_ID");
        authorized = isAuthorized(data);
        (new CWE284_P10_V1_SilentBeaconSafeSink()).applySilentBeaconDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P10_V1_SilentBeaconSafeSink {
    public void applySilentBeaconDeletion() throws SQLException {
        String data = CWE284_P10_V1_SilentBeaconSafe.data;
        boolean authorized = CWE284_P10_V1_SilentBeaconSafe.authorized;
        Connection silentBeaconConnection = DriverManager.getConnection("jdbc:hsqldb:mem:silentBeacon");
        try {
            PreparedStatement silentBeaconDelete = silentBeaconConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            silentBeaconDelete.setString(1, data);
            if (authorized) {
                silentBeaconDelete.executeUpdate();
            } else {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            silentBeaconConnection.close();
        }
    }
}
