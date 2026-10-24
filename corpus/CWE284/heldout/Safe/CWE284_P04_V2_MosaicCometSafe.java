import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P04_V2_MosaicCometSafe {

    private boolean checkMosaicCometAccess(String accountId) {
        boolean authorized = isAuthorized(accountId);
        return authorized;
    }

    public void deleteMosaicCometAccount() throws SQLException {
        String data;
        if (5 == 5) {
            data = System.getenv("MOSAIC_COMET_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = checkMosaicCometAccess(data);
        Connection mosaicCometConnection = DriverManager.getConnection("jdbc:hsqldb:mem:mosaicComet");
        try {
            PreparedStatement mosaicCometDelete = mosaicCometConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            mosaicCometDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                mosaicCometDelete.executeUpdate();
            }
        } finally {
            mosaicCometConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
