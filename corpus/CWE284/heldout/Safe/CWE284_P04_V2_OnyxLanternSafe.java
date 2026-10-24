import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P04_V2_OnyxLanternSafe {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    private boolean checkOnyxLanternAccess(String accountId) {
        boolean authorized = isAuthorized(accountId);
        return authorized;
    }

    public void deleteOnyxLanternAccount() throws SQLException {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = System.getenv("ONYX_LANTERN_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = checkOnyxLanternAccess(data);
        Connection onyxLanternConnection = DriverManager.getConnection("jdbc:hsqldb:mem:onyxLantern");
        try {
            PreparedStatement onyxLanternDelete = onyxLanternConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            onyxLanternDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                onyxLanternDelete.executeUpdate();
            }
        } finally {
            onyxLanternConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
