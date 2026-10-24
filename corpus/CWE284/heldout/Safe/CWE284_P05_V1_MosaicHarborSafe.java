import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P05_V1_MosaicHarborSafe {

    private String mosaicHarborAccountId;

    private boolean mosaicHarborAuthorized;

    private void applyMosaicHarborDeletion() throws SQLException {
        String data = mosaicHarborAccountId;
        boolean authorized = mosaicHarborAuthorized;
        Connection mosaicHarborConnection = DriverManager.getConnection("jdbc:hsqldb:mem:mosaicHarbor");
        try {
            PreparedStatement mosaicHarborDelete = mosaicHarborConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            mosaicHarborDelete.setString(1, data);
            if (authorized) {
                mosaicHarborDelete.executeUpdate();
            }
        } finally {
            mosaicHarborConnection.close();
        }
    }

    public void deleteMosaicHarborAccount() throws SQLException {
        String data;
        data = System.getenv("MOSAIC_HARBOR_ACCOUNT_ID");
        mosaicHarborAccountId = data;
        mosaicHarborAuthorized = isAuthorized(data);
        applyMosaicHarborDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
