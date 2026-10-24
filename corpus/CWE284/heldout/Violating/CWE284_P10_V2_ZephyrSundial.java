import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P10_V2_ZephyrSundial {

    public static String data;

    public static boolean authorized;

    public void deleteZephyrSundialAccount() throws SQLException {
        switch (7) {
        case 7:
            data = System.getenv("ZEPHYR_SUNDIAL_ACCOUNT_ID");
            break;
        default:
            data = null;
            break;
        }
        authorized = isAuthorized(data);
        (new CWE284_P10_V2_ZephyrSundialSink()).applyZephyrSundialDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P10_V2_ZephyrSundialSink {
    public void applyZephyrSundialDeletion() throws SQLException {
        String data = CWE284_P10_V2_ZephyrSundial.data;
        boolean authorized = CWE284_P10_V2_ZephyrSundial.authorized;
        Connection zephyrSundialConnection = DriverManager.getConnection("jdbc:hsqldb:mem:zephyrSundial");
        try {
            PreparedStatement zephyrSundialDelete = zephyrSundialConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            zephyrSundialDelete.setString(1, data);
            zephyrSundialDelete.executeUpdate();
            if (!authorized) {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            zephyrSundialConnection.close();
        }
    }
}
