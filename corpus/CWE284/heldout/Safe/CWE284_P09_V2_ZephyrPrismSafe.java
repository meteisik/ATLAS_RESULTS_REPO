import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P09_V2_ZephyrPrismSafe {
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

    public void deleteZephyrPrismAccount() throws SQLException {
        String data;
        if (IO.STATIC_FINAL_TRUE) {
            data = System.getenv("ZEPHYR_PRISM_ACCOUNT_ID");
        } else {
            data = null;
        }
        Container request = new Container();
        request.accountId = data;
        request.authorized = isAuthorized(data);
        (new CWE284_P09_V2_ZephyrPrismSafeSink()).applyZephyrPrismDeletion(request);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P09_V2_ZephyrPrismSafeSink {
    public void applyZephyrPrismDeletion(CWE284_P09_V2_ZephyrPrismSafe.Container request) throws SQLException {
        String data = request.accountId;
        boolean authorized = request.authorized;
        Connection zephyrPrismConnection = DriverManager.getConnection("jdbc:hsqldb:mem:zephyrPrism");
        try {
            PreparedStatement zephyrPrismDelete = zephyrPrismConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            zephyrPrismDelete.setString(1, data);
            if (authorized) {
                zephyrPrismDelete.executeUpdate();
            }
        } finally {
            zephyrPrismConnection.close();
        }
    }
}
