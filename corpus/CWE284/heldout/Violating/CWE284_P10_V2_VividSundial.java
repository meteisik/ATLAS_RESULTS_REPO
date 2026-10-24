import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P10_V2_VividSundial {
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
        (new CWE284_P10_V2_VividSundialSink()).applyVividSundialDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P10_V2_VividSundialSink {
    public void applyVividSundialDeletion() throws SQLException {
        String data = CWE284_P10_V2_VividSundial.data;
        boolean authorized = CWE284_P10_V2_VividSundial.authorized;
        Connection vividSundialConnection = DriverManager.getConnection("jdbc:hsqldb:mem:vividSundial");
        try {
            PreparedStatement vividSundialDelete = vividSundialConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            vividSundialDelete.setString(1, data);
            vividSundialDelete.executeUpdate();
            if (!authorized) {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            vividSundialConnection.close();
        }
    }
}
