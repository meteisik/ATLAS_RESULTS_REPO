import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P10_V2_ZephyrQuartz {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public static String data;

    public static boolean authorized;

    public void deleteZephyrQuartzAccount() throws SQLException {
        if (IO.STATIC_FINAL_FIVE == 5) {
            data = System.getenv("ZEPHYR_QUARTZ_ACCOUNT_ID");
        } else {
            data = null;
        }
        authorized = isAuthorized(data);
        (new CWE284_P10_V2_ZephyrQuartzSink()).applyZephyrQuartzDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P10_V2_ZephyrQuartzSink {
    public void applyZephyrQuartzDeletion() throws SQLException {
        String data = CWE284_P10_V2_ZephyrQuartz.data;
        boolean authorized = CWE284_P10_V2_ZephyrQuartz.authorized;
        Connection zephyrQuartzConnection = DriverManager.getConnection("jdbc:hsqldb:mem:zephyrQuartz");
        try {
            PreparedStatement zephyrQuartzDelete = zephyrQuartzConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            zephyrQuartzDelete.setString(1, data);
            zephyrQuartzDelete.executeUpdate();
            if (!authorized) {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            zephyrQuartzConnection.close();
        }
    }
}
