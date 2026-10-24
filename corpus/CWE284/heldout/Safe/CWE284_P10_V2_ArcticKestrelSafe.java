import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P10_V2_ArcticKestrelSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public static String data;

    public static boolean authorized;

    public void deleteArcticKestrelAccount() throws SQLException {
        if (IO.staticFive == 5) {
            data = System.getenv("ARCTIC_KESTREL_ACCOUNT_ID");
        } else {
            data = null;
        }
        authorized = isAuthorized(data);
        (new CWE284_P10_V2_ArcticKestrelSafeSink()).applyArcticKestrelDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P10_V2_ArcticKestrelSafeSink {
    public void applyArcticKestrelDeletion() throws SQLException {
        String data = CWE284_P10_V2_ArcticKestrelSafe.data;
        boolean authorized = CWE284_P10_V2_ArcticKestrelSafe.authorized;
        Connection arcticKestrelConnection = DriverManager.getConnection("jdbc:hsqldb:mem:arcticKestrel");
        try {
            PreparedStatement arcticKestrelDelete = arcticKestrelConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            arcticKestrelDelete.setString(1, data);
            if (authorized) {
                arcticKestrelDelete.executeUpdate();
            } else {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            arcticKestrelConnection.close();
        }
    }
}
