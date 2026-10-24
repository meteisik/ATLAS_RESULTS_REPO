import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P01_V2_IvoryRavenSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void deleteIvoryRavenAccount() throws SQLException {
        String data;
        if (IO.STATIC_FINAL_FIVE == 5) {
            data = System.getenv("IVORY_RAVEN_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = isAuthorized(data);
        Connection ivoryRavenConnection = DriverManager.getConnection("jdbc:hsqldb:mem:ivoryRaven");
        try {
            PreparedStatement ivoryRavenDelete = ivoryRavenConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            ivoryRavenDelete.setString(1, data);
            if (authorized) {
                ivoryRavenDelete.executeUpdate();
            }
        } finally {
            ivoryRavenConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
