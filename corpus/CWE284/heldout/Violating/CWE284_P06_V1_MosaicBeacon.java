import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P06_V1_MosaicBeacon {

    public void deleteMosaicBeaconAccount() throws SQLException {
        String data;
        data = System.getenv("MOSAIC_BEACON_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        (new CWE284_P06_V1_MosaicBeaconSink()).applyMosaicBeaconDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P06_V1_MosaicBeaconSink {
    public void applyMosaicBeaconDeletion(String data, boolean authorized) throws SQLException {
        Connection mosaicBeaconConnection = DriverManager.getConnection("jdbc:hsqldb:mem:mosaicBeacon");
        try {
            PreparedStatement mosaicBeaconDelete = mosaicBeaconConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            mosaicBeaconDelete.setString(1, data);
            mosaicBeaconDelete.executeUpdate();
            if (!authorized) {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            mosaicBeaconConnection.close();
        }
    }
}
