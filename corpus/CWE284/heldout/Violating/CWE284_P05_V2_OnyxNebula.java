import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P05_V2_OnyxNebula {
    private static boolean privateReturnsTrue() { return true; }

    private String onyxNebulaAccountId;

    private boolean onyxNebulaAuthorized;

    private void applyOnyxNebulaDeletion() throws SQLException {
        String data = onyxNebulaAccountId;
        boolean authorized = onyxNebulaAuthorized;
        Connection onyxNebulaConnection = DriverManager.getConnection("jdbc:hsqldb:mem:onyxNebula");
        try {
            PreparedStatement onyxNebulaDelete = onyxNebulaConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            onyxNebulaDelete.setString(1, data);
            onyxNebulaDelete.executeUpdate();
        } finally {
            onyxNebulaConnection.close();
        }
    }

    public void deleteOnyxNebulaAccount() throws SQLException {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("ONYX_NEBULA_ACCOUNT_ID");
        } else {
            data = null;
        }
        onyxNebulaAccountId = data;
        onyxNebulaAuthorized = isAuthorized(data);
        applyOnyxNebulaDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
