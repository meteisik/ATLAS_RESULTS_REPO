import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P04_V2_MosaicOrbitSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private boolean checkMosaicOrbitAccess(String accountId) {
        boolean authorized = isAuthorized(accountId);
        return authorized;
    }

    public void deleteMosaicOrbitAccount() throws SQLException {
        String data;
        if (IO.staticTrue) {
            data = System.getenv("MOSAIC_ORBIT_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = checkMosaicOrbitAccess(data);
        Connection mosaicOrbitConnection = DriverManager.getConnection("jdbc:hsqldb:mem:mosaicOrbit");
        try {
            PreparedStatement mosaicOrbitDelete = mosaicOrbitConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            mosaicOrbitDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                mosaicOrbitDelete.executeUpdate();
            }
        } finally {
            mosaicOrbitConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
