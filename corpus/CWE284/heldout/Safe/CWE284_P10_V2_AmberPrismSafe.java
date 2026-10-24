import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P10_V2_AmberPrismSafe {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public static String data;

    public static boolean authorized;

    public void deleteAmberPrismAccount() throws SQLException {
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("AMBER_PRISM_ACCOUNT_ID");
        } else {
            data = null;
        }
        authorized = isAuthorized(data);
        (new CWE284_P10_V2_AmberPrismSafeSink()).applyAmberPrismDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P10_V2_AmberPrismSafeSink {
    public void applyAmberPrismDeletion() throws SQLException {
        String data = CWE284_P10_V2_AmberPrismSafe.data;
        boolean authorized = CWE284_P10_V2_AmberPrismSafe.authorized;
        Connection amberPrismConnection = DriverManager.getConnection("jdbc:hsqldb:mem:amberPrism");
        try {
            PreparedStatement amberPrismDelete = amberPrismConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            amberPrismDelete.setString(1, data);
            if (authorized) {
                amberPrismDelete.executeUpdate();
            } else {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            amberPrismConnection.close();
        }
    }
}
