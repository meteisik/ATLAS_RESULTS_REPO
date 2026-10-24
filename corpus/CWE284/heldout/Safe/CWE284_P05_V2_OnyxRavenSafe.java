import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P05_V2_OnyxRavenSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private String onyxRavenAccountId;

    private boolean onyxRavenAuthorized;

    private void applyOnyxRavenDeletion() throws SQLException {
        String data = onyxRavenAccountId;
        boolean authorized = onyxRavenAuthorized;
        Connection onyxRavenConnection = DriverManager.getConnection("jdbc:hsqldb:mem:onyxRaven");
        try {
            PreparedStatement onyxRavenDelete = onyxRavenConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            onyxRavenDelete.setString(1, data);
            if (authorized) {
                onyxRavenDelete.executeUpdate();
            }
        } finally {
            onyxRavenConnection.close();
        }
    }

    public void deleteOnyxRavenAccount() throws SQLException {
        String data;
        if (IO.staticTrue) {
            data = System.getenv("ONYX_RAVEN_ACCOUNT_ID");
        } else {
            data = null;
        }
        onyxRavenAccountId = data;
        onyxRavenAuthorized = isAuthorized(data);
        applyOnyxRavenDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
