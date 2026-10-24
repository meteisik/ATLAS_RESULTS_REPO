import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P06_V1_MosaicOrbit {

    public void deleteMosaicOrbitAccount() throws SQLException {
        String data;
        data = System.getenv("MOSAIC_ORBIT_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        (new CWE284_P06_V1_MosaicOrbitSink()).applyMosaicOrbitDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P06_V1_MosaicOrbitSink {
    public void applyMosaicOrbitDeletion(String data, boolean authorized) throws SQLException {
        Connection mosaicOrbitConnection = DriverManager.getConnection("jdbc:hsqldb:mem:mosaicOrbit");
        try {
            PreparedStatement mosaicOrbitDelete = mosaicOrbitConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            mosaicOrbitDelete.setString(1, data);
            mosaicOrbitDelete.executeUpdate();
            if (!authorized) {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            mosaicOrbitConnection.close();
        }
    }
}
