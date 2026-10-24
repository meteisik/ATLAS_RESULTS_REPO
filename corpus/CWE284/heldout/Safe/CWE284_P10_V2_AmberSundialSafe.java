import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P10_V2_AmberSundialSafe {
    private static boolean privateReturnsTrue() { return true; }

    public static String data;

    public static boolean authorized;

    public void deleteAmberSundialAccount() throws SQLException {
        if (privateReturnsTrue()) {
            data = System.getenv("AMBER_SUNDIAL_ACCOUNT_ID");
        } else {
            data = null;
        }
        authorized = isAuthorized(data);
        (new CWE284_P10_V2_AmberSundialSafeSink()).applyAmberSundialDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P10_V2_AmberSundialSafeSink {
    public void applyAmberSundialDeletion() throws SQLException {
        String data = CWE284_P10_V2_AmberSundialSafe.data;
        boolean authorized = CWE284_P10_V2_AmberSundialSafe.authorized;
        Connection amberSundialConnection = DriverManager.getConnection("jdbc:hsqldb:mem:amberSundial");
        try {
            PreparedStatement amberSundialDelete = amberSundialConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            amberSundialDelete.setString(1, data);
            if (authorized) {
                amberSundialDelete.executeUpdate();
            } else {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            amberSundialConnection.close();
        }
    }
}
