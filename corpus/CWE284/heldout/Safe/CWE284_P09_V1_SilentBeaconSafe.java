import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P09_V1_SilentBeaconSafe {

    static class Container {
        public String accountId;
        public boolean authorized;
    }

    public void deleteSilentBeaconAccount() throws SQLException {
        String data;
        data = System.getenv("SILENT_BEACON_ACCOUNT_ID");
        Container request = new Container();
        request.accountId = data;
        request.authorized = isAuthorized(data);
        (new CWE284_P09_V1_SilentBeaconSafeSink()).applySilentBeaconDeletion(request);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P09_V1_SilentBeaconSafeSink {
    public void applySilentBeaconDeletion(CWE284_P09_V1_SilentBeaconSafe.Container request) throws SQLException {
        String data = request.accountId;
        boolean authorized = request.authorized;
        Connection silentBeaconConnection = DriverManager.getConnection("jdbc:hsqldb:mem:silentBeacon");
        try {
            PreparedStatement silentBeaconDelete = silentBeaconConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            silentBeaconDelete.setString(1, data);
            if (authorized) {
                silentBeaconDelete.executeUpdate();
            }
        } finally {
            silentBeaconConnection.close();
        }
    }
}
