import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P03_V2_MosaicLotusSafe {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    private void applyMosaicLotusDeletion(String data, boolean authorized) throws SQLException {
        Connection mosaicLotusConnection = DriverManager.getConnection("jdbc:hsqldb:mem:mosaicLotus");
        try {
            PreparedStatement mosaicLotusDelete = mosaicLotusConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            mosaicLotusDelete.setString(1, data);
            if (authorized) {
                mosaicLotusDelete.executeUpdate();
            }
        } finally {
            mosaicLotusConnection.close();
        }
    }

    public void deleteMosaicLotusAccount() throws SQLException {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("MOSAIC_LOTUS_ACCOUNT_ID");
        } else {
            data = null;
        }
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(data);
        applyMosaicLotusDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
