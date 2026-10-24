import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P07_V1_MosaicLantern {

    public void deleteMosaicLanternAccount() throws SQLException {
        String data;
        data = System.getenv("MOSAIC_LANTERN_ACCOUNT_ID");
        String requester = System.getProperty("user.name");
        boolean authorized = (new CWE284_P07_V1_MosaicLanternChecker()).isAuthorized(requester);
        Connection mosaicLanternConnection = DriverManager.getConnection("jdbc:hsqldb:mem:mosaicLantern");
        try {
            PreparedStatement mosaicLanternDelete = mosaicLanternConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            mosaicLanternDelete.setString(1, data);
            if (authorized) {
                mosaicLanternDelete.executeUpdate();
            }
        } finally {
            mosaicLanternConnection.close();
        }
    }
}

class CWE284_P07_V1_MosaicLanternChecker {
    public boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        boolean authorized = operator != null && operator.equals(accountId);
        return authorized;
    }
}
