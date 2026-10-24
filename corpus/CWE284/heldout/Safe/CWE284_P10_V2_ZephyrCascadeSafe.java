import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P10_V2_ZephyrCascadeSafe {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public static String data;

    public static boolean authorized;

    public void deleteZephyrCascadeAccount() throws SQLException {
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("ZEPHYR_CASCADE_ACCOUNT_ID");
        } else {
            data = null;
        }
        authorized = isAuthorized(data);
        (new CWE284_P10_V2_ZephyrCascadeSafeSink()).applyZephyrCascadeDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P10_V2_ZephyrCascadeSafeSink {
    public void applyZephyrCascadeDeletion() throws SQLException {
        String data = CWE284_P10_V2_ZephyrCascadeSafe.data;
        boolean authorized = CWE284_P10_V2_ZephyrCascadeSafe.authorized;
        Connection zephyrCascadeConnection = DriverManager.getConnection("jdbc:hsqldb:mem:zephyrCascade");
        try {
            PreparedStatement zephyrCascadeDelete = zephyrCascadeConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            zephyrCascadeDelete.setString(1, data);
            if (authorized) {
                zephyrCascadeDelete.executeUpdate();
            } else {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            zephyrCascadeConnection.close();
        }
    }
}
