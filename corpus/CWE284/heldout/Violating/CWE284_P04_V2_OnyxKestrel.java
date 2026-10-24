import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P04_V2_OnyxKestrel {

    private boolean checkOnyxKestrelAccess(String accountId) {
        boolean authorized = isAuthorized(accountId);
        return authorized;
    }

    public void deleteOnyxKestrelAccount() throws SQLException {
        String data;
        if (5 == 5) {
            data = System.getenv("ONYX_KESTREL_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = checkOnyxKestrelAccess(data);
        Connection onyxKestrelConnection = DriverManager.getConnection("jdbc:hsqldb:mem:onyxKestrel");
        try {
            PreparedStatement onyxKestrelDelete = onyxKestrelConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            onyxKestrelDelete.setString(1, data);
            if (authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                onyxKestrelDelete.executeUpdate();
            }
        } finally {
            onyxKestrelConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
