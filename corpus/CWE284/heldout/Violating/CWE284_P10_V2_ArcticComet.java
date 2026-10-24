import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P10_V2_ArcticComet {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public static String data;

    public static boolean authorized;

    public void deleteArcticCometAccount() throws SQLException {
        if (IO.staticTrue) {
            data = System.getenv("ARCTIC_COMET_ACCOUNT_ID");
        } else {
            data = null;
        }
        authorized = isAuthorized(data);
        (new CWE284_P10_V2_ArcticCometSink()).applyArcticCometDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P10_V2_ArcticCometSink {
    public void applyArcticCometDeletion() throws SQLException {
        String data = CWE284_P10_V2_ArcticComet.data;
        boolean authorized = CWE284_P10_V2_ArcticComet.authorized;
        Connection arcticCometConnection = DriverManager.getConnection("jdbc:hsqldb:mem:arcticComet");
        try {
            PreparedStatement arcticCometDelete = arcticCometConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            arcticCometDelete.setString(1, data);
            arcticCometDelete.executeUpdate();
            if (!authorized) {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            arcticCometConnection.close();
        }
    }
}
