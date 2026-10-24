import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P09_V2_ArcticBeaconSafe {
    private static int privateFive = 5;

    static class Container {
        public String accountId;
        public boolean authorized;
    }

    public void deleteArcticBeaconAccount() throws SQLException {
        String data;
        if (privateFive == 5) {
            data = System.getenv("ARCTIC_BEACON_ACCOUNT_ID");
        } else {
            data = null;
        }
        Container request = new Container();
        request.accountId = data;
        request.authorized = isAuthorized(data);
        (new CWE284_P09_V2_ArcticBeaconSafeSink()).applyArcticBeaconDeletion(request);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P09_V2_ArcticBeaconSafeSink {
    public void applyArcticBeaconDeletion(CWE284_P09_V2_ArcticBeaconSafe.Container request) throws SQLException {
        String data = request.accountId;
        boolean authorized = request.authorized;
        Connection arcticBeaconConnection = DriverManager.getConnection("jdbc:hsqldb:mem:arcticBeacon");
        try {
            PreparedStatement arcticBeaconDelete = arcticBeaconConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            arcticBeaconDelete.setString(1, data);
            if (authorized) {
                arcticBeaconDelete.executeUpdate();
            }
        } finally {
            arcticBeaconConnection.close();
        }
    }
}
