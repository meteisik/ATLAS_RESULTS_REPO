import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P09_V1_OnyxBeacon {

    static class Container {
        public String accountId;
        public boolean authorized;
    }

    public void deleteOnyxBeaconAccount() throws SQLException {
        String data;
        data = System.getenv("ONYX_BEACON_ACCOUNT_ID");
        Container request = new Container();
        request.accountId = data;
        request.authorized = isAuthorized(data);
        (new CWE284_P09_V1_OnyxBeaconSink()).applyOnyxBeaconDeletion(request);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P09_V1_OnyxBeaconSink {
    public void applyOnyxBeaconDeletion(CWE284_P09_V1_OnyxBeacon.Container request) throws SQLException {
        String data = request.accountId;
        boolean authorized = request.authorized;
        Connection onyxBeaconConnection = DriverManager.getConnection("jdbc:hsqldb:mem:onyxBeacon");
        try {
            PreparedStatement onyxBeaconDelete = onyxBeaconConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            onyxBeaconDelete.setString(1, data);
            onyxBeaconDelete.executeUpdate();
        } finally {
            onyxBeaconConnection.close();
        }
    }
}
