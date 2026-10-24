import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P05_V1_MosaicLantern {

    private String mosaicLanternAccountId;

    private boolean mosaicLanternAuthorized;

    private void applyMosaicLanternDeletion() throws SQLException {
        String data = mosaicLanternAccountId;
        boolean authorized = mosaicLanternAuthorized;
        Connection mosaicLanternConnection = DriverManager.getConnection("jdbc:hsqldb:mem:mosaicLantern");
        try {
            PreparedStatement mosaicLanternDelete = mosaicLanternConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            mosaicLanternDelete.setString(1, data);
            mosaicLanternDelete.executeUpdate();
        } finally {
            mosaicLanternConnection.close();
        }
    }

    public void deleteMosaicLanternAccount() throws SQLException {
        String data;
        data = System.getenv("MOSAIC_LANTERN_ACCOUNT_ID");
        mosaicLanternAccountId = data;
        mosaicLanternAuthorized = isAuthorized(data);
        applyMosaicLanternDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
