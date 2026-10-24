import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P03_V1_CrimsonBeacon {

    private void applyCrimsonBeaconDeletion(String data, boolean authorized) throws SQLException {
        Connection crimsonBeaconConnection = DriverManager.getConnection("jdbc:hsqldb:mem:crimsonBeacon");
        try {
            PreparedStatement crimsonBeaconDelete = crimsonBeaconConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            crimsonBeaconDelete.setString(1, data);
            if (authorized) {
                crimsonBeaconDelete.executeUpdate();
            }
        } finally {
            crimsonBeaconConnection.close();
        }
    }

    public void deleteCrimsonBeaconAccount() throws SQLException {
        String data;
        data = System.getenv("CRIMSON_BEACON_ACCOUNT_ID");
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(requester);
        applyCrimsonBeaconDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
