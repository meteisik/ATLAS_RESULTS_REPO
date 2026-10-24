import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P10_V2_ArcticHelixSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public static String data;

    public static boolean authorized;

    public void deleteArcticHelixAccount() throws SQLException {
        if (IO.STATIC_FINAL_FIVE == 5) {
            data = System.getenv("ARCTIC_HELIX_ACCOUNT_ID");
        } else {
            data = null;
        }
        authorized = isAuthorized(data);
        (new CWE284_P10_V2_ArcticHelixSafeSink()).applyArcticHelixDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P10_V2_ArcticHelixSafeSink {
    public void applyArcticHelixDeletion() throws SQLException {
        String data = CWE284_P10_V2_ArcticHelixSafe.data;
        boolean authorized = CWE284_P10_V2_ArcticHelixSafe.authorized;
        Connection arcticHelixConnection = DriverManager.getConnection("jdbc:hsqldb:mem:arcticHelix");
        try {
            PreparedStatement arcticHelixDelete = arcticHelixConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            arcticHelixDelete.setString(1, data);
            if (authorized) {
                arcticHelixDelete.executeUpdate();
            } else {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            arcticHelixConnection.close();
        }
    }
}
