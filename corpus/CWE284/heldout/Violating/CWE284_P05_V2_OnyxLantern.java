import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P05_V2_OnyxLantern {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    private String onyxLanternAccountId;

    private boolean onyxLanternAuthorized;

    private void applyOnyxLanternDeletion() throws SQLException {
        String data = onyxLanternAccountId;
        boolean authorized = onyxLanternAuthorized;
        Connection onyxLanternConnection = DriverManager.getConnection("jdbc:hsqldb:mem:onyxLantern");
        try {
            PreparedStatement onyxLanternDelete = onyxLanternConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            onyxLanternDelete.setString(1, data);
            onyxLanternDelete.executeUpdate();
        } finally {
            onyxLanternConnection.close();
        }
    }

    public void deleteOnyxLanternAccount() throws SQLException {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("ONYX_LANTERN_ACCOUNT_ID");
        } else {
            data = null;
        }
        onyxLanternAccountId = data;
        onyxLanternAuthorized = isAuthorized(data);
        applyOnyxLanternDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
