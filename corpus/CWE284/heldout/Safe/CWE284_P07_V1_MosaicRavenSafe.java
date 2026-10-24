import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P07_V1_MosaicRavenSafe {

    public void deleteMosaicRavenAccount() throws SQLException {
        String data;
        data = System.getenv("MOSAIC_RAVEN_ACCOUNT_ID");
        String requester = System.getProperty("user.name");
        boolean authorized = (new CWE284_P07_V1_MosaicRavenSafeChecker()).isAuthorized(data);
        Connection mosaicRavenConnection = DriverManager.getConnection("jdbc:hsqldb:mem:mosaicRaven");
        try {
            PreparedStatement mosaicRavenDelete = mosaicRavenConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            mosaicRavenDelete.setString(1, data);
            if (authorized) {
                mosaicRavenDelete.executeUpdate();
            }
        } finally {
            mosaicRavenConnection.close();
        }
    }
}

class CWE284_P07_V1_MosaicRavenSafeChecker {
    public boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        boolean authorized = operator != null && operator.equals(accountId);
        return authorized;
    }
}
