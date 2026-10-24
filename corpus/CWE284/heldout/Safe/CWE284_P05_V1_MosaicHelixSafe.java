import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P05_V1_MosaicHelixSafe {

    private String mosaicHelixAccountId;

    private boolean mosaicHelixAuthorized;

    private void applyMosaicHelixDeletion() throws SQLException {
        String data = mosaicHelixAccountId;
        boolean authorized = mosaicHelixAuthorized;
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
        data = System.getenv("MOSAIC_HELIX_ACCOUNT_ID");
        mosaicHelixAccountId = data;
        mosaicHelixAuthorized = isAuthorized(data);
        applyMosaicHelixDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
