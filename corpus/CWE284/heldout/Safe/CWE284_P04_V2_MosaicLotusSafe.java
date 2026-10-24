import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P04_V2_MosaicLotusSafe {
    private static boolean privateReturnsTrue() { return true; }

    private boolean checkMosaicLotusAccess(String accountId) {
        boolean authorized = isAuthorized(accountId);
        return authorized;
    }

    public void deleteMosaicLotusAccount() throws SQLException {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("MOSAIC_LOTUS_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = checkMosaicLotusAccess(data);
        Connection mosaicLotusConnection = DriverManager.getConnection("jdbc:hsqldb:mem:mosaicLotus");
        try {
            PreparedStatement mosaicLotusDelete = mosaicLotusConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            mosaicLotusDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                mosaicLotusDelete.executeUpdate();
            }
        } finally {
            mosaicLotusConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
