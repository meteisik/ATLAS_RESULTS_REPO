import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P09_V2_AmberAuroraSafe {
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

    public void deleteAmberAuroraAccount() throws SQLException {
        String data;
        if (IO.staticFive == 5) {
            data = System.getenv("AMBER_AURORA_ACCOUNT_ID");
        } else {
            data = null;
        }
        Container request = new Container();
        request.accountId = data;
        request.authorized = isAuthorized(data);
        (new CWE284_P09_V2_AmberAuroraSafeSink()).applyAmberAuroraDeletion(request);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P09_V2_AmberAuroraSafeSink {
    public void applyAmberAuroraDeletion(CWE284_P09_V2_AmberAuroraSafe.Container request) throws SQLException {
        String data = request.accountId;
        boolean authorized = request.authorized;
        Connection amberAuroraConnection = DriverManager.getConnection("jdbc:hsqldb:mem:amberAurora");
        try {
            PreparedStatement amberAuroraDelete = amberAuroraConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            amberAuroraDelete.setString(1, data);
            if (authorized) {
                amberAuroraDelete.executeUpdate();
            }
        } finally {
            amberAuroraConnection.close();
        }
    }
}
