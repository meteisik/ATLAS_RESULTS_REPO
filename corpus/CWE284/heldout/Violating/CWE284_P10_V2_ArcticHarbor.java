import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P10_V2_ArcticHarbor {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public static String data;

    public static boolean authorized;

    public void deleteArcticHarborAccount() throws SQLException {
        if (IO.staticReturnsTrue()) {
            data = System.getenv("ARCTIC_HARBOR_ACCOUNT_ID");
        } else {
            data = null;
        }
        authorized = isAuthorized(data);
        (new CWE284_P10_V2_ArcticHarborSink()).applyArcticHarborDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P10_V2_ArcticHarborSink {
    public void applyArcticHarborDeletion() throws SQLException {
        String data = CWE284_P10_V2_ArcticHarbor.data;
        boolean authorized = CWE284_P10_V2_ArcticHarbor.authorized;
        Connection arcticHarborConnection = DriverManager.getConnection("jdbc:hsqldb:mem:arcticHarbor");
        try {
            PreparedStatement arcticHarborDelete = arcticHarborConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            arcticHarborDelete.setString(1, data);
            arcticHarborDelete.executeUpdate();
            if (!authorized) {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            arcticHarborConnection.close();
        }
    }
}
