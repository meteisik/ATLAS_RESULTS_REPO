import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P03_V2_MosaicHelixSafe {

    private void applyMosaicHelixDeletion(String data, boolean authorized) throws SQLException {
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

    public void deleteMosaicHelixAccount() throws SQLException {
        String data;
        if (5 == 5) {
            data = System.getenv("MOSAIC_HELIX_ACCOUNT_ID");
        } else {
            data = null;
        }
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(data);
        applyMosaicHelixDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
