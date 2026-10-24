import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P10_V2_ZephyrPrismSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public static String data;

    public static boolean authorized;

    public void deleteZephyrPrismAccount() throws SQLException {
        if (IO.staticReturnsTrue()) {
            data = System.getenv("ZEPHYR_PRISM_ACCOUNT_ID");
        } else {
            data = null;
        }
        authorized = isAuthorized(data);
        (new CWE284_P10_V2_ZephyrPrismSafeSink()).applyZephyrPrismDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P10_V2_ZephyrPrismSafeSink {
    public void applyZephyrPrismDeletion() throws SQLException {
        String data = CWE284_P10_V2_ZephyrPrismSafe.data;
        boolean authorized = CWE284_P10_V2_ZephyrPrismSafe.authorized;
        Connection zephyrPrismConnection = DriverManager.getConnection("jdbc:hsqldb:mem:zephyrPrism");
        try {
            PreparedStatement zephyrPrismDelete = zephyrPrismConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            zephyrPrismDelete.setString(1, data);
            if (authorized) {
                zephyrPrismDelete.executeUpdate();
            } else {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            zephyrPrismConnection.close();
        }
    }
}
