import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P05_V2_OnyxOrbitSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private String onyxOrbitAccountId;

    private boolean onyxOrbitAuthorized;

    private void applyOnyxOrbitDeletion() throws SQLException {
        String data = onyxOrbitAccountId;
        boolean authorized = onyxOrbitAuthorized;
        Connection onyxOrbitConnection = DriverManager.getConnection("jdbc:hsqldb:mem:onyxOrbit");
        try {
            PreparedStatement onyxOrbitDelete = onyxOrbitConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            onyxOrbitDelete.setString(1, data);
            if (authorized) {
                onyxOrbitDelete.executeUpdate();
            }
        } finally {
            onyxOrbitConnection.close();
        }
    }

    public void deleteOnyxOrbitAccount() throws SQLException {
        String data;
        if (IO.STATIC_FINAL_TRUE) {
            data = System.getenv("ONYX_ORBIT_ACCOUNT_ID");
        } else {
            data = null;
        }
        onyxOrbitAccountId = data;
        onyxOrbitAuthorized = isAuthorized(data);
        applyOnyxOrbitDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
