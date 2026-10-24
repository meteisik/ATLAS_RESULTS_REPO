import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P03_V2_MosaicComet {

    private void applyMosaicCometDeletion(String data, boolean authorized) throws SQLException {
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
        data = null;
        for (int j = 0; j < 1; j++) {
            data = System.getenv("MOSAIC_COMET_ACCOUNT_ID");
        }
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(requester);
        applyMosaicCometDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
