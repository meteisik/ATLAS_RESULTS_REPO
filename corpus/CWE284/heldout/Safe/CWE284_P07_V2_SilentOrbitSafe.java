import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P07_V2_SilentOrbitSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void deleteSilentOrbitAccount() throws SQLException {
        String data;
        if (IO.STATIC_FINAL_TRUE) {
            data = System.getenv("SILENT_ORBIT_ACCOUNT_ID");
        } else {
            data = null;
        }
        String requester = System.getProperty("user.name");
        boolean authorized = (new CWE284_P07_V2_SilentOrbitSafeChecker()).isAuthorized(data);
        Connection silentOrbitConnection = DriverManager.getConnection("jdbc:hsqldb:mem:silentOrbit");
        try {
            PreparedStatement silentOrbitDelete = silentOrbitConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            silentOrbitDelete.setString(1, data);
            if (authorized) {
                silentOrbitDelete.executeUpdate();
            }
        } finally {
            silentOrbitConnection.close();
        }
    }
}

class CWE284_P07_V2_SilentOrbitSafeChecker {
    public boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        boolean authorized = operator != null && operator.equals(accountId);
        return authorized;
    }
}
