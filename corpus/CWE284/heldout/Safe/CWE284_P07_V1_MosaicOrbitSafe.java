import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P07_V1_MosaicOrbitSafe {

    public void deleteMosaicOrbitAccount() throws SQLException {
        String data;
        data = System.getenv("MOSAIC_ORBIT_ACCOUNT_ID");
        String requester = System.getProperty("user.name");
        boolean authorized = (new CWE284_P07_V1_MosaicOrbitSafeChecker()).isAuthorized(data);
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
}

class CWE284_P07_V1_MosaicOrbitSafeChecker {
    public boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        boolean authorized = operator != null && operator.equals(accountId);
        return authorized;
    }
}
