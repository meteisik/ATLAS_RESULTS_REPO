import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P06_V2_OnyxHelix {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public void deleteOnyxHelixAccount() throws SQLException {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("ONYX_HELIX_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = isAuthorized(data);
        (new CWE284_P06_V2_OnyxHelixSink()).applyOnyxHelixDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P06_V2_OnyxHelixSink {
    public void applyOnyxHelixDeletion(String data, boolean authorized) throws SQLException {
        Connection onyxHelixConnection = DriverManager.getConnection("jdbc:hsqldb:mem:onyxHelix");
        try {
            PreparedStatement onyxHelixDelete = onyxHelixConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            onyxHelixDelete.setString(1, data);
            onyxHelixDelete.executeUpdate();
            if (!authorized) {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            onyxHelixConnection.close();
        }
    }
}
