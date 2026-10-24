import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P07_V1_MosaicHelix {

    public void deleteMosaicHelixAccount() throws SQLException {
        String data;
        data = System.getenv("MOSAIC_HELIX_ACCOUNT_ID");
        String requester = System.getProperty("user.name");
        boolean authorized = (new CWE284_P07_V1_MosaicHelixChecker()).isAuthorized(requester);
        Connection mosaicHelixConnection = DriverManager.getConnection("jdbc:hsqldb:mem:mosaicHelix");
        try {
            PreparedStatement mosaicHelixDelete = mosaicHelixConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            mosaicHelixDelete.setString(1, data);
            if (authorized) {
                mosaicHelixDelete.executeUpdate();
            }
        } finally {
            mosaicHelixConnection.close();
        }
    }
}

class CWE284_P07_V1_MosaicHelixChecker {
    public boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        boolean authorized = operator != null && operator.equals(accountId);
        return authorized;
    }
}
