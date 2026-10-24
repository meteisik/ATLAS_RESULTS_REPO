import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P07_V1_MosaicKestrelSafe {

    public void deleteMosaicKestrelAccount() throws SQLException {
        String data;
        data = System.getenv("MOSAIC_KESTREL_ACCOUNT_ID");
        String requester = System.getProperty("user.name");
        boolean authorized = (new CWE284_P07_V1_MosaicKestrelSafeChecker()).isAuthorized(data);
        Connection mosaicKestrelConnection = DriverManager.getConnection("jdbc:hsqldb:mem:mosaicKestrel");
        try {
            PreparedStatement mosaicKestrelDelete = mosaicKestrelConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            mosaicKestrelDelete.setString(1, data);
            if (authorized) {
                mosaicKestrelDelete.executeUpdate();
            }
        } finally {
            mosaicKestrelConnection.close();
        }
    }
}

class CWE284_P07_V1_MosaicKestrelSafeChecker {
    public boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        boolean authorized = operator != null && operator.equals(accountId);
        return authorized;
    }
}
