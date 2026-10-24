import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P09_V2_ZephyrSundial {
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

    public void deleteZephyrSundialAccount() throws SQLException {
        String data;
        if (IO.STATIC_FINAL_FIVE == 5) {
            data = System.getenv("ZEPHYR_SUNDIAL_ACCOUNT_ID");
        } else {
            data = null;
        }
        Container request = new Container();
        request.accountId = data;
        request.authorized = isAuthorized(data);
        (new CWE284_P09_V2_ZephyrSundialSink()).applyZephyrSundialDeletion(request);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P09_V2_ZephyrSundialSink {
    public void applyZephyrSundialDeletion(CWE284_P09_V2_ZephyrSundial.Container request) throws SQLException {
        String data = request.accountId;
        boolean authorized = request.authorized;
        Connection zephyrSundialConnection = DriverManager.getConnection("jdbc:hsqldb:mem:zephyrSundial");
        try {
            PreparedStatement zephyrSundialDelete = zephyrSundialConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            zephyrSundialDelete.setString(1, data);
            zephyrSundialDelete.executeUpdate();
        } finally {
            zephyrSundialConnection.close();
        }
    }
}
