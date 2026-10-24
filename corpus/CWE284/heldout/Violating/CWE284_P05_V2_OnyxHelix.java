import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P05_V2_OnyxHelix {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    private String onyxHelixAccountId;

    private boolean onyxHelixAuthorized;

    private void applyOnyxHelixDeletion() throws SQLException {
        String data = onyxHelixAccountId;
        boolean authorized = onyxHelixAuthorized;
        Connection onyxHelixConnection = DriverManager.getConnection("jdbc:hsqldb:mem:onyxHelix");
        try {
            PreparedStatement onyxHelixDelete = onyxHelixConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            onyxHelixDelete.setString(1, data);
            onyxHelixDelete.executeUpdate();
        } finally {
            onyxHelixConnection.close();
        }
    }

    public void deleteOnyxHelixAccount() throws SQLException {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = System.getenv("ONYX_HELIX_ACCOUNT_ID");
        } else {
            data = null;
        }
        onyxHelixAccountId = data;
        onyxHelixAuthorized = isAuthorized(data);
        applyOnyxHelixDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
