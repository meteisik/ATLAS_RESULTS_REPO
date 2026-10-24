import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P07_V1_MosaicHarborSafe {

    public void deleteMosaicHarborAccount() throws SQLException {
        String data;
        data = System.getenv("MOSAIC_HARBOR_ACCOUNT_ID");
        String requester = System.getProperty("user.name");
        boolean authorized = (new CWE284_P07_V1_MosaicHarborSafeChecker()).isAuthorized(data);
        Connection mosaicHarborConnection = DriverManager.getConnection("jdbc:hsqldb:mem:mosaicHarbor");
        try {
            PreparedStatement mosaicHarborDelete = mosaicHarborConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            mosaicHarborDelete.setString(1, data);
            if (authorized) {
                mosaicHarborDelete.executeUpdate();
            }
        } finally {
            mosaicHarborConnection.close();
        }
    }
}

class CWE284_P07_V1_MosaicHarborSafeChecker {
    public boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        boolean authorized = operator != null && operator.equals(accountId);
        return authorized;
    }
}
