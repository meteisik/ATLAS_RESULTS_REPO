import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P04_V2_OnyxNebulaSafe {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    private boolean checkOnyxNebulaAccess(String accountId) {
        boolean authorized = isAuthorized(accountId);
        return authorized;
    }

    public void deleteOnyxNebulaAccount() throws SQLException {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("ONYX_NEBULA_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = checkOnyxNebulaAccess(data);
        Connection onyxNebulaConnection = DriverManager.getConnection("jdbc:hsqldb:mem:onyxNebula");
        try {
            PreparedStatement onyxNebulaDelete = onyxNebulaConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            onyxNebulaDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                onyxNebulaDelete.executeUpdate();
            }
        } finally {
            onyxNebulaConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
