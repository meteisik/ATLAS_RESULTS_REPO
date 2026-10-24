import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P10_V2_ZephyrAurora {
    private static boolean privateTrue = true;

    public static String data;

    public static boolean authorized;

    public void deleteZephyrAuroraAccount() throws SQLException {
        if (privateTrue) {
            data = System.getenv("ZEPHYR_AURORA_ACCOUNT_ID");
        } else {
            data = null;
        }
        authorized = isAuthorized(data);
        (new CWE284_P10_V2_ZephyrAuroraSink()).applyZephyrAuroraDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P10_V2_ZephyrAuroraSink {
    public void applyZephyrAuroraDeletion() throws SQLException {
        String data = CWE284_P10_V2_ZephyrAurora.data;
        boolean authorized = CWE284_P10_V2_ZephyrAurora.authorized;
        Connection zephyrAuroraConnection = DriverManager.getConnection("jdbc:hsqldb:mem:zephyrAurora");
        try {
            PreparedStatement zephyrAuroraDelete = zephyrAuroraConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            zephyrAuroraDelete.setString(1, data);
            zephyrAuroraDelete.executeUpdate();
            if (!authorized) {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            zephyrAuroraConnection.close();
        }
    }
}
