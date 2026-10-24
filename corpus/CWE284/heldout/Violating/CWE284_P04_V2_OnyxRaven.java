import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P04_V2_OnyxRaven {
    private static boolean privateReturnsTrue() { return true; }

    private boolean checkOnyxRavenAccess(String accountId) {
        boolean authorized = isAuthorized(accountId);
        return authorized;
    }

    public void deleteOnyxRavenAccount() throws SQLException {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("ONYX_RAVEN_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = checkOnyxRavenAccess(data);
        Connection onyxRavenConnection = DriverManager.getConnection("jdbc:hsqldb:mem:onyxRaven");
        try {
            PreparedStatement onyxRavenDelete = onyxRavenConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            onyxRavenDelete.setString(1, data);
            if (authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                onyxRavenDelete.executeUpdate();
            }
        } finally {
            onyxRavenConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
