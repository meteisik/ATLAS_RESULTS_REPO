import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P09_V1_RuneBeaconSafe {

    static class Container {
        public String accountId;
        public boolean authorized;
    }

    public void deleteRuneBeaconAccount() throws SQLException {
        String data;
        data = System.getenv("RUNE_BEACON_ACCOUNT_ID");
        Container request = new Container();
        request.accountId = data;
        request.authorized = isAuthorized(data);
        (new CWE284_P09_V1_RuneBeaconSafeSink()).applyRuneBeaconDeletion(request);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P09_V1_RuneBeaconSafeSink {
    public void applyRuneBeaconDeletion(CWE284_P09_V1_RuneBeaconSafe.Container request) throws SQLException {
        String data = request.accountId;
        boolean authorized = request.authorized;
        Connection runeBeaconConnection = DriverManager.getConnection("jdbc:hsqldb:mem:runeBeacon");
        try {
            PreparedStatement runeBeaconDelete = runeBeaconConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            runeBeaconDelete.setString(1, data);
            if (authorized) {
                runeBeaconDelete.executeUpdate();
            }
        } finally {
            runeBeaconConnection.close();
        }
    }
}
