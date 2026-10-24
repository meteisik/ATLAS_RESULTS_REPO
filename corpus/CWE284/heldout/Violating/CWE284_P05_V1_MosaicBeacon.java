import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P05_V1_MosaicBeacon {

    private String mosaicBeaconAccountId;

    private boolean mosaicBeaconAuthorized;

    private void applyMosaicBeaconDeletion() throws SQLException {
        String data = mosaicBeaconAccountId;
        boolean authorized = mosaicBeaconAuthorized;
        Connection mosaicBeaconConnection = DriverManager.getConnection("jdbc:hsqldb:mem:mosaicBeacon");
        try {
            PreparedStatement mosaicBeaconDelete = mosaicBeaconConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            mosaicBeaconDelete.setString(1, data);
            mosaicBeaconDelete.executeUpdate();
        } finally {
            mosaicBeaconConnection.close();
        }
    }

    public void deleteMosaicBeaconAccount() throws SQLException {
        String data;
        data = System.getenv("MOSAIC_BEACON_ACCOUNT_ID");
        mosaicBeaconAccountId = data;
        mosaicBeaconAuthorized = isAuthorized(data);
        applyMosaicBeaconDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
