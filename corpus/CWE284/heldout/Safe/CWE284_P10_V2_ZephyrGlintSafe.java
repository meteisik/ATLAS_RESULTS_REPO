import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P10_V2_ZephyrGlintSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public static String data;

    public static boolean authorized;

    public void deleteZephyrGlintAccount() throws SQLException {
        if (IO.STATIC_FINAL_TRUE) {
            data = System.getenv("ZEPHYR_GLINT_ACCOUNT_ID");
        } else {
            data = null;
        }
        authorized = isAuthorized(data);
        (new CWE284_P10_V2_ZephyrGlintSafeSink()).applyZephyrGlintDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P10_V2_ZephyrGlintSafeSink {
    public void applyZephyrGlintDeletion() throws SQLException {
        String data = CWE284_P10_V2_ZephyrGlintSafe.data;
        boolean authorized = CWE284_P10_V2_ZephyrGlintSafe.authorized;
        Connection zephyrGlintConnection = DriverManager.getConnection("jdbc:hsqldb:mem:zephyrGlint");
        try {
            PreparedStatement zephyrGlintDelete = zephyrGlintConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            zephyrGlintDelete.setString(1, data);
            if (authorized) {
                zephyrGlintDelete.executeUpdate();
            } else {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            zephyrGlintConnection.close();
        }
    }
}
