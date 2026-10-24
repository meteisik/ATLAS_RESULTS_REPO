import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P04_V2_MosaicBeaconSafe {

    private boolean checkMosaicBeaconAccess(String accountId) {
        boolean authorized = isAuthorized(accountId);
        return authorized;
    }

    public void deleteMosaicBeaconAccount() throws SQLException {
        String data;
        if (true) {
            data = System.getenv("MOSAIC_BEACON_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = checkMosaicBeaconAccess(data);
        Connection mosaicBeaconConnection = DriverManager.getConnection("jdbc:hsqldb:mem:mosaicBeacon");
        try {
            PreparedStatement mosaicBeaconDelete = mosaicBeaconConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            mosaicBeaconDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                mosaicBeaconDelete.executeUpdate();
            }
        } finally {
            mosaicBeaconConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
