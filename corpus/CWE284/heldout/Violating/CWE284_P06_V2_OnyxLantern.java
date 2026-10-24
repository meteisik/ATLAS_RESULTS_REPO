import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P06_V2_OnyxLantern {
    private static boolean privateReturnsTrue() { return true; }

    public void deleteOnyxLanternAccount() throws SQLException {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("ONYX_LANTERN_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = isAuthorized(data);
        (new CWE284_P06_V2_OnyxLanternSink()).applyOnyxLanternDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P06_V2_OnyxLanternSink {
    public void applyOnyxLanternDeletion(String data, boolean authorized) throws SQLException {
        Connection onyxLanternConnection = DriverManager.getConnection("jdbc:hsqldb:mem:onyxLantern");
        try {
            PreparedStatement onyxLanternDelete = onyxLanternConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            onyxLanternDelete.setString(1, data);
            onyxLanternDelete.executeUpdate();
            if (!authorized) {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            onyxLanternConnection.close();
        }
    }
}
