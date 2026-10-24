import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P04_V2_MosaicKestrelSafe {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    private boolean checkMosaicKestrelAccess(String accountId) {
        boolean authorized = isAuthorized(accountId);
        return authorized;
    }

    public void deleteMosaicKestrelAccount() throws SQLException {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("MOSAIC_KESTREL_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = checkMosaicKestrelAccess(data);
        Connection mosaicKestrelConnection = DriverManager.getConnection("jdbc:hsqldb:mem:mosaicKestrel");
        try {
            PreparedStatement mosaicKestrelDelete = mosaicKestrelConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            mosaicKestrelDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                mosaicKestrelDelete.executeUpdate();
            }
        } finally {
            mosaicKestrelConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
