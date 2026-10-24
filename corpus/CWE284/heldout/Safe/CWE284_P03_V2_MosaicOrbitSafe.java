import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P03_V2_MosaicOrbitSafe {
    private static boolean privateReturnsTrue() { return true; }

    private void applyMosaicOrbitDeletion(String data, boolean authorized) throws SQLException {
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
        if (privateReturnsTrue()) {
            data = System.getenv("MOSAIC_ORBIT_ACCOUNT_ID");
        } else {
            data = null;
        }
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(data);
        applyMosaicOrbitDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
