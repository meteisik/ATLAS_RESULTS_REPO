import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P10_V2_VividSundialSafe {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public static String data;

    public static boolean authorized;

    public void deleteVividSundialAccount() throws SQLException {
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = System.getenv("VIVID_SUNDIAL_ACCOUNT_ID");
        } else {
            data = null;
        }
        authorized = isAuthorized(data);
        (new CWE284_P10_V2_VividSundialSafeSink()).applyVividSundialDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P10_V2_VividSundialSafeSink {
    public void applyVividSundialDeletion() throws SQLException {
        String data = CWE284_P10_V2_VividSundialSafe.data;
        boolean authorized = CWE284_P10_V2_VividSundialSafe.authorized;
        Connection vividSundialConnection = DriverManager.getConnection("jdbc:hsqldb:mem:vividSundial");
        try {
            PreparedStatement vividSundialDelete = vividSundialConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            vividSundialDelete.setString(1, data);
            if (authorized) {
                vividSundialDelete.executeUpdate();
            } else {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            vividSundialConnection.close();
        }
    }
}
