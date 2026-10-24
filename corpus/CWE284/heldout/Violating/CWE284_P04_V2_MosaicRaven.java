import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P04_V2_MosaicRaven {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private boolean checkMosaicRavenAccess(String accountId) {
        boolean authorized = isAuthorized(accountId);
        return authorized;
    }

    public void deleteMosaicRavenAccount() throws SQLException {
        String data;
        if (IO.staticReturnsTrue()) {
            data = System.getenv("MOSAIC_RAVEN_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = checkMosaicRavenAccess(data);
        Connection mosaicRavenConnection = DriverManager.getConnection("jdbc:hsqldb:mem:mosaicRaven");
        try {
            PreparedStatement mosaicRavenDelete = mosaicRavenConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            mosaicRavenDelete.setString(1, data);
            if (authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                mosaicRavenDelete.executeUpdate();
            }
        } finally {
            mosaicRavenConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
