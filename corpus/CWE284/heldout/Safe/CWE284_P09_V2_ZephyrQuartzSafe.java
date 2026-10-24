import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P09_V2_ZephyrQuartzSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    static class Container {
        public String accountId;
        public boolean authorized;
    }

    public void deleteZephyrQuartzAccount() throws SQLException {
        String data;
        if (IO.staticTrue) {
            data = System.getenv("ZEPHYR_QUARTZ_ACCOUNT_ID");
        } else {
            data = null;
        }
        Container request = new Container();
        request.accountId = data;
        request.authorized = isAuthorized(data);
        (new CWE284_P09_V2_ZephyrQuartzSafeSink()).applyZephyrQuartzDeletion(request);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P09_V2_ZephyrQuartzSafeSink {
    public void applyZephyrQuartzDeletion(CWE284_P09_V2_ZephyrQuartzSafe.Container request) throws SQLException {
        String data = request.accountId;
        boolean authorized = request.authorized;
        Connection zephyrQuartzConnection = DriverManager.getConnection("jdbc:hsqldb:mem:zephyrQuartz");
        try {
            PreparedStatement zephyrQuartzDelete = zephyrQuartzConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            zephyrQuartzDelete.setString(1, data);
            if (authorized) {
                zephyrQuartzDelete.executeUpdate();
            }
        } finally {
            zephyrQuartzConnection.close();
        }
    }
}
