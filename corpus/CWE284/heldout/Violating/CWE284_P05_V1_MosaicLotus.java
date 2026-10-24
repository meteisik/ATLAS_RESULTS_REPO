import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P05_V1_MosaicLotus {

    private String mosaicLotusAccountId;

    private boolean mosaicLotusAuthorized;

    private void applyMosaicLotusDeletion() throws SQLException {
        String data = mosaicLotusAccountId;
        boolean authorized = mosaicLotusAuthorized;
        Connection mosaicLotusConnection = DriverManager.getConnection("jdbc:hsqldb:mem:mosaicLotus");
        try {
            PreparedStatement mosaicLotusDelete = mosaicLotusConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            mosaicLotusDelete.setString(1, data);
            mosaicLotusDelete.executeUpdate();
        } finally {
            mosaicLotusConnection.close();
        }
    }

    public void deleteMosaicLotusAccount() throws SQLException {
        String data;
        data = System.getenv("MOSAIC_LOTUS_ACCOUNT_ID");
        mosaicLotusAccountId = data;
        mosaicLotusAuthorized = isAuthorized(data);
        applyMosaicLotusDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
