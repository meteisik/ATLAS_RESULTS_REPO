import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P06_V1_MosaicLanternSafe {

    public void deleteMosaicLanternAccount() throws SQLException {
        String data;
        data = System.getenv("MOSAIC_LANTERN_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        (new CWE284_P06_V1_MosaicLanternSafeSink()).applyMosaicLanternDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P06_V1_MosaicLanternSafeSink {
    public void applyMosaicLanternDeletion(String data, boolean authorized) throws SQLException {
        Connection mosaicLanternConnection = DriverManager.getConnection("jdbc:hsqldb:mem:mosaicLantern");
        try {
            PreparedStatement mosaicLanternDelete = mosaicLanternConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            mosaicLanternDelete.setString(1, data);
            if (authorized) {
                mosaicLanternDelete.executeUpdate();
            } else {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            mosaicLanternConnection.close();
        }
    }
}
