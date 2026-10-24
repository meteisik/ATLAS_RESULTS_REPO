import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P03_V2_MosaicBeacon {

    private void applyMosaicBeaconDeletion(String data, boolean authorized) throws SQLException {
        Connection mosaicBeaconConnection = DriverManager.getConnection("jdbc:hsqldb:mem:mosaicBeacon");
        try {
            PreparedStatement mosaicBeaconDelete = mosaicBeaconConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            mosaicBeaconDelete.setString(1, data);
            if (authorized) {
                mosaicBeaconDelete.executeUpdate();
            }
        } finally {
            mosaicBeaconConnection.close();
        }
    }

    public void deleteMosaicBeaconAccount() throws SQLException {
        String data;
        while (true) {
            data = System.getenv("MOSAIC_BEACON_ACCOUNT_ID");
            break;
        }
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(requester);
        applyMosaicBeaconDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
