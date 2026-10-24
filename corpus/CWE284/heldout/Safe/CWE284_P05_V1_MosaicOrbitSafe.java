import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P05_V1_MosaicOrbitSafe {

    private String mosaicOrbitAccountId;

    private boolean mosaicOrbitAuthorized;

    private void applyMosaicOrbitDeletion() throws SQLException {
        String data = mosaicOrbitAccountId;
        boolean authorized = mosaicOrbitAuthorized;
        Connection mosaicOrbitConnection = DriverManager.getConnection("jdbc:hsqldb:mem:mosaicOrbit");
        try {
            PreparedStatement mosaicOrbitDelete = mosaicOrbitConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            mosaicOrbitDelete.setString(1, data);
            if (authorized) {
                mosaicOrbitDelete.executeUpdate();
            }
        } finally {
            mosaicOrbitConnection.close();
        }
    }

    public void deleteMosaicOrbitAccount() throws SQLException {
        String data;
        data = System.getenv("MOSAIC_ORBIT_ACCOUNT_ID");
        mosaicOrbitAccountId = data;
        mosaicOrbitAuthorized = isAuthorized(data);
        applyMosaicOrbitDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
