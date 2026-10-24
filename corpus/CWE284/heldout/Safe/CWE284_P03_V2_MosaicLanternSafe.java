import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P03_V2_MosaicLanternSafe {
    private static boolean privateTrue = true;

    private void applyMosaicLanternDeletion(String data, boolean authorized) throws SQLException {
        Connection mosaicLanternConnection = DriverManager.getConnection("jdbc:hsqldb:mem:mosaicLantern");
        try {
            PreparedStatement mosaicLanternDelete = mosaicLanternConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            mosaicLanternDelete.setString(1, data);
            if (authorized) {
                mosaicLanternDelete.executeUpdate();
            }
        } finally {
            mosaicLanternConnection.close();
        }
    }

    public void deleteMosaicLanternAccount() throws SQLException {
        String data;
        if (privateTrue) {
            data = System.getenv("MOSAIC_LANTERN_ACCOUNT_ID");
        } else {
            data = null;
        }
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(data);
        applyMosaicLanternDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
