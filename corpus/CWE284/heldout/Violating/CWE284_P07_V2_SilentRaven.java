import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P07_V2_SilentRaven {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void deleteSilentRavenAccount() throws SQLException {
        String data;
        if (IO.staticTrue) {
            data = System.getenv("SILENT_RAVEN_ACCOUNT_ID");
        } else {
            data = null;
        }
        String requester = System.getProperty("user.name");
        boolean authorized = (new CWE284_P07_V2_SilentRavenChecker()).isAuthorized(requester);
        Connection silentRavenConnection = DriverManager.getConnection("jdbc:hsqldb:mem:silentRaven");
        try {
            PreparedStatement silentRavenDelete = silentRavenConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            silentRavenDelete.setString(1, data);
            if (authorized) {
                silentRavenDelete.executeUpdate();
            }
        } finally {
            silentRavenConnection.close();
        }
    }
}

class CWE284_P07_V2_SilentRavenChecker {
    public boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        boolean authorized = operator != null && operator.equals(accountId);
        return authorized;
    }
}
