import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P05_V2_OnyxKestrelSafe {
    private static boolean privateTrue = true;

    private String onyxKestrelAccountId;

    private boolean onyxKestrelAuthorized;

    private void applyOnyxKestrelDeletion() throws SQLException {
        String data = onyxKestrelAccountId;
        boolean authorized = onyxKestrelAuthorized;
        Connection onyxKestrelConnection = DriverManager.getConnection("jdbc:hsqldb:mem:onyxKestrel");
        try {
            PreparedStatement onyxKestrelDelete = onyxKestrelConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            onyxKestrelDelete.setString(1, data);
            if (authorized) {
                onyxKestrelDelete.executeUpdate();
            }
        } finally {
            onyxKestrelConnection.close();
        }
    }

    public void deleteOnyxKestrelAccount() throws SQLException {
        String data;
        if (privateTrue) {
            data = System.getenv("ONYX_KESTREL_ACCOUNT_ID");
        } else {
            data = null;
        }
        onyxKestrelAccountId = data;
        onyxKestrelAuthorized = isAuthorized(data);
        applyOnyxKestrelDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
