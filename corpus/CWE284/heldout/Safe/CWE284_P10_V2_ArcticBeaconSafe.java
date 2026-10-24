import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P10_V2_ArcticBeaconSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public static String data;

    public static boolean authorized;

    public void deleteArcticBeaconAccount() throws SQLException {
        if (IO.STATIC_FINAL_TRUE) {
            data = System.getenv("ARCTIC_BEACON_ACCOUNT_ID");
        } else {
            data = null;
        }
        authorized = isAuthorized(data);
        (new CWE284_P10_V2_ArcticBeaconSafeSink()).applyArcticBeaconDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P10_V2_ArcticBeaconSafeSink {
    public void applyArcticBeaconDeletion() throws SQLException {
        String data = CWE284_P10_V2_ArcticBeaconSafe.data;
        boolean authorized = CWE284_P10_V2_ArcticBeaconSafe.authorized;
        Connection arcticBeaconConnection = DriverManager.getConnection("jdbc:hsqldb:mem:arcticBeacon");
        try {
            PreparedStatement arcticBeaconDelete = arcticBeaconConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            arcticBeaconDelete.setString(1, data);
            if (authorized) {
                arcticBeaconDelete.executeUpdate();
            } else {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            arcticBeaconConnection.close();
        }
    }
}
