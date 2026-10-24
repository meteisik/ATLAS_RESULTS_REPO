import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P07_V1_MosaicComet {

    public void deleteMosaicCometAccount() throws SQLException {
        String data;
        data = System.getenv("MOSAIC_COMET_ACCOUNT_ID");
        String requester = System.getProperty("user.name");
        boolean authorized = (new CWE284_P07_V1_MosaicCometChecker()).isAuthorized(requester);
        Connection mosaicCometConnection = DriverManager.getConnection("jdbc:hsqldb:mem:mosaicComet");
        try {
            PreparedStatement mosaicCometDelete = mosaicCometConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            mosaicCometDelete.setString(1, data);
            if (authorized) {
                mosaicCometDelete.executeUpdate();
            }
        } finally {
            mosaicCometConnection.close();
        }
    }
}

class CWE284_P07_V1_MosaicCometChecker {
    public boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        boolean authorized = operator != null && operator.equals(accountId);
        return authorized;
    }
}
