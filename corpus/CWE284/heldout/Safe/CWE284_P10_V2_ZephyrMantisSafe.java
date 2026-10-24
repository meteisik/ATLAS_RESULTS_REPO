import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P10_V2_ZephyrMantisSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public static String data;

    public static boolean authorized;

    public void deleteZephyrMantisAccount() throws SQLException {
        if (IO.staticTrue) {
            data = System.getenv("ZEPHYR_MANTIS_ACCOUNT_ID");
        } else {
            data = null;
        }
        authorized = isAuthorized(data);
        (new CWE284_P10_V2_ZephyrMantisSafeSink()).applyZephyrMantisDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P10_V2_ZephyrMantisSafeSink {
    public void applyZephyrMantisDeletion() throws SQLException {
        String data = CWE284_P10_V2_ZephyrMantisSafe.data;
        boolean authorized = CWE284_P10_V2_ZephyrMantisSafe.authorized;
        Connection zephyrMantisConnection = DriverManager.getConnection("jdbc:hsqldb:mem:zephyrMantis");
        try {
            PreparedStatement zephyrMantisDelete = zephyrMantisConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            zephyrMantisDelete.setString(1, data);
            if (authorized) {
                zephyrMantisDelete.executeUpdate();
            } else {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            zephyrMantisConnection.close();
        }
    }
}
