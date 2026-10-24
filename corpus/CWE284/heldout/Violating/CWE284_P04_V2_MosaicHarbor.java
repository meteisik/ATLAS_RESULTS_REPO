import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P04_V2_MosaicHarbor {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    private boolean checkMosaicHarborAccess(String accountId) {
        boolean authorized = isAuthorized(accountId);
        return authorized;
    }

    public void deleteMosaicHarborAccount() throws SQLException {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = System.getenv("MOSAIC_HARBOR_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = checkMosaicHarborAccess(data);
        Connection mosaicHarborConnection = DriverManager.getConnection("jdbc:hsqldb:mem:mosaicHarbor");
        try {
            PreparedStatement mosaicHarborDelete = mosaicHarborConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            mosaicHarborDelete.setString(1, data);
            if (authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                mosaicHarborDelete.executeUpdate();
            }
        } finally {
            mosaicHarborConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
