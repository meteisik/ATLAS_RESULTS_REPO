import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P04_V2_OnyxHelixSafe {

    private boolean checkOnyxHelixAccess(String accountId) {
        boolean authorized = isAuthorized(accountId);
        return authorized;
    }

    public void deleteOnyxHelixAccount() throws SQLException {
        String data;
        if (true) {
            data = System.getenv("ONYX_HELIX_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = checkOnyxHelixAccess(data);
        Connection onyxHelixConnection = DriverManager.getConnection("jdbc:hsqldb:mem:onyxHelix");
        try {
            PreparedStatement onyxHelixDelete = onyxHelixConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            onyxHelixDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                onyxHelixDelete.executeUpdate();
            }
        } finally {
            onyxHelixConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
