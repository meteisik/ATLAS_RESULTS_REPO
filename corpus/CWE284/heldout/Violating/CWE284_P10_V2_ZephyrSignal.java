import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P10_V2_ZephyrSignal {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public static String data;

    public static boolean authorized;

    public void deleteZephyrSignalAccount() throws SQLException {
        if (IO.staticFive == 5) {
            data = System.getenv("ZEPHYR_SIGNAL_ACCOUNT_ID");
        } else {
            data = null;
        }
        authorized = isAuthorized(data);
        (new CWE284_P10_V2_ZephyrSignalSink()).applyZephyrSignalDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P10_V2_ZephyrSignalSink {
    public void applyZephyrSignalDeletion() throws SQLException {
        String data = CWE284_P10_V2_ZephyrSignal.data;
        boolean authorized = CWE284_P10_V2_ZephyrSignal.authorized;
        Connection zephyrSignalConnection = DriverManager.getConnection("jdbc:hsqldb:mem:zephyrSignal");
        try {
            PreparedStatement zephyrSignalDelete = zephyrSignalConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            zephyrSignalDelete.setString(1, data);
            zephyrSignalDelete.executeUpdate();
            if (!authorized) {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            zephyrSignalConnection.close();
        }
    }
}
