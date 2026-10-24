import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P04_V2_MosaicLanternSafe {
    private static int privateFive = 5;

    private boolean checkMosaicLanternAccess(String accountId) {
        boolean authorized = isAuthorized(accountId);
        return authorized;
    }

    public void deleteMosaicLanternAccount() throws SQLException {
        String data;
        if (privateFive == 5) {
            data = System.getenv("MOSAIC_LANTERN_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = checkMosaicLanternAccess(data);
        Connection mosaicLanternConnection = DriverManager.getConnection("jdbc:hsqldb:mem:mosaicLantern");
        try {
            PreparedStatement mosaicLanternDelete = mosaicLanternConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            mosaicLanternDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                mosaicLanternDelete.executeUpdate();
            }
        } finally {
            mosaicLanternConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
