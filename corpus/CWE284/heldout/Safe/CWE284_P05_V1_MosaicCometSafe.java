import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P05_V1_MosaicCometSafe {

    private String mosaicCometAccountId;

    private boolean mosaicCometAuthorized;

    private void applyMosaicCometDeletion() throws SQLException {
        String data = mosaicCometAccountId;
        boolean authorized = mosaicCometAuthorized;
        Connection mosaicCometConnection = DriverManager.getConnection("jdbc:hsqldb:mem:mosaicComet");
        try {
            PreparedStatement mosaicCometDelete = mosaicCometConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            mosaicCometDelete.setString(1, data);
            if (authorized) {
                mosaicCometDelete.executeUpdate();
            }
        } finally {
            mosaicCometConnection.close();
        }
    }

    public void deleteMosaicCometAccount() throws SQLException {
        String data;
        data = System.getenv("MOSAIC_COMET_ACCOUNT_ID");
        mosaicCometAccountId = data;
        mosaicCometAuthorized = isAuthorized(data);
        applyMosaicCometDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
