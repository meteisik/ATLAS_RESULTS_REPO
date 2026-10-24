import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P01_V1_ArcticBeaconSafe {

    public void deleteArcticBeaconAccount() throws SQLException {
        String data;
        data = System.getenv("ARCTIC_BEACON_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
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

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
