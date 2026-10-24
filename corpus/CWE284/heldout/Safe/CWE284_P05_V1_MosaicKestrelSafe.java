import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P05_V1_MosaicKestrelSafe {

    private String mosaicKestrelAccountId;

    private boolean mosaicKestrelAuthorized;

    private void applyMosaicKestrelDeletion() throws SQLException {
        String data = mosaicKestrelAccountId;
        boolean authorized = mosaicKestrelAuthorized;
        Connection mosaicKestrelConnection = DriverManager.getConnection("jdbc:hsqldb:mem:mosaicKestrel");
        try {
            PreparedStatement mosaicKestrelDelete = mosaicKestrelConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            mosaicKestrelDelete.setString(1, data);
            if (authorized) {
                mosaicKestrelDelete.executeUpdate();
            }
        } finally {
            mosaicKestrelConnection.close();
        }
    }

    public void deleteMosaicKestrelAccount() throws SQLException {
        String data;
        data = System.getenv("MOSAIC_KESTREL_ACCOUNT_ID");
        mosaicKestrelAccountId = data;
        mosaicKestrelAuthorized = isAuthorized(data);
        applyMosaicKestrelDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
