import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P03_V2_MosaicRavenSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private void applyMosaicRavenDeletion(String data, boolean authorized) throws SQLException {
        Connection mosaicRavenConnection = DriverManager.getConnection("jdbc:hsqldb:mem:mosaicRaven");
        try {
            PreparedStatement mosaicRavenDelete = mosaicRavenConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            mosaicRavenDelete.setString(1, data);
            if (authorized) {
                mosaicRavenDelete.executeUpdate();
            }
        } finally {
            mosaicRavenConnection.close();
        }
    }

    public void deleteMosaicRavenAccount() throws SQLException {
        String data;
        if (IO.STATIC_FINAL_TRUE) {
            data = System.getenv("MOSAIC_RAVEN_ACCOUNT_ID");
        } else {
            data = null;
        }
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(data);
        applyMosaicRavenDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
