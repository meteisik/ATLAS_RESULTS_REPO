import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P07_V1_MosaicLotusSafe {

    public void deleteMosaicLotusAccount() throws SQLException {
        String data;
        data = System.getenv("MOSAIC_LOTUS_ACCOUNT_ID");
        String requester = System.getProperty("user.name");
        boolean authorized = (new CWE284_P07_V1_MosaicLotusSafeChecker()).isAuthorized(data);
        Connection mosaicLotusConnection = DriverManager.getConnection("jdbc:hsqldb:mem:mosaicLotus");
        try {
            PreparedStatement mosaicLotusDelete = mosaicLotusConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            mosaicLotusDelete.setString(1, data);
            if (authorized) {
                mosaicLotusDelete.executeUpdate();
            }
        } finally {
            mosaicLotusConnection.close();
        }
    }
}

class CWE284_P07_V1_MosaicLotusSafeChecker {
    public boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        boolean authorized = operator != null && operator.equals(accountId);
        return authorized;
    }
}
