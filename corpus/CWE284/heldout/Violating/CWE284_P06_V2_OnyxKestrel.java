import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P06_V2_OnyxKestrel {
    private static int privateFive = 5;

    public void deleteOnyxKestrelAccount() throws SQLException {
        String data;
        if (privateFive == 5) {
            data = System.getenv("ONYX_KESTREL_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = isAuthorized(data);
        (new CWE284_P06_V2_OnyxKestrelSink()).applyOnyxKestrelDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P06_V2_OnyxKestrelSink {
    public void applyOnyxKestrelDeletion(String data, boolean authorized) throws SQLException {
        Connection onyxKestrelConnection = DriverManager.getConnection("jdbc:hsqldb:mem:onyxKestrel");
        try {
            PreparedStatement onyxKestrelDelete = onyxKestrelConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            onyxKestrelDelete.setString(1, data);
            onyxKestrelDelete.executeUpdate();
            if (!authorized) {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            onyxKestrelConnection.close();
        }
    }
}
