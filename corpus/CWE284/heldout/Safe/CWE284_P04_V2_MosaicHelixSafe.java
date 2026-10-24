import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P04_V2_MosaicHelixSafe {
    private static boolean privateTrue = true;

    private boolean checkMosaicHelixAccess(String accountId) {
        boolean authorized = isAuthorized(accountId);
        return authorized;
    }

    public void deleteMosaicHelixAccount() throws SQLException {
        String data;
        if (privateTrue) {
            data = System.getenv("MOSAIC_HELIX_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = checkMosaicHelixAccess(data);
        Connection mosaicHelixConnection = DriverManager.getConnection("jdbc:hsqldb:mem:mosaicHelix");
        try {
            PreparedStatement mosaicHelixDelete = mosaicHelixConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            mosaicHelixDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                mosaicHelixDelete.executeUpdate();
            }
        } finally {
            mosaicHelixConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
