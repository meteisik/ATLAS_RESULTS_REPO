import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P10_V2_ZephyrFlareSafe {
    private static boolean privateReturnsTrue() { return true; }

    public static String data;

    public static boolean authorized;

    public void deleteZephyrFlareAccount() throws SQLException {
        if (privateReturnsTrue()) {
            data = System.getenv("ZEPHYR_FLARE_ACCOUNT_ID");
        } else {
            data = null;
        }
        authorized = isAuthorized(data);
        (new CWE284_P10_V2_ZephyrFlareSafeSink()).applyZephyrFlareDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P10_V2_ZephyrFlareSafeSink {
    public void applyZephyrFlareDeletion() throws SQLException {
        String data = CWE284_P10_V2_ZephyrFlareSafe.data;
        boolean authorized = CWE284_P10_V2_ZephyrFlareSafe.authorized;
        Connection zephyrFlareConnection = DriverManager.getConnection("jdbc:hsqldb:mem:zephyrFlare");
        try {
            PreparedStatement zephyrFlareDelete = zephyrFlareConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            zephyrFlareDelete.setString(1, data);
            if (authorized) {
                zephyrFlareDelete.executeUpdate();
            } else {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            zephyrFlareConnection.close();
        }
    }
}
