import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.HashMap;

public class CWE284_P11_V2_ArcticBeacon {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void deleteArcticBeaconAccount() throws SQLException {
        String data;
        if (IO.staticReturnsTrue()) {
            data = System.getenv("ARCTIC_BEACON_ACCOUNT_ID");
        } else {
            data = null;
        }
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(requester);
        HashMap<Integer, Boolean> decisions = new HashMap<Integer, Boolean>();
        decisions.put(0, authorized);
        decisions.put(1, authorized);
        decisions.put(2, authorized);
        (new CWE284_P11_V2_ArcticBeaconSink()).applyArcticBeaconDeletion(data, decisions);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P11_V2_ArcticBeaconSink {
    public void applyArcticBeaconDeletion(String data, HashMap<Integer, Boolean> decisions) throws SQLException {
        boolean authorized = decisions.get(2);
        Connection arcticBeaconConnection = DriverManager.getConnection("jdbc:hsqldb:mem:arcticBeacon");
        try {
            PreparedStatement arcticBeaconDelete = arcticBeaconConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            arcticBeaconDelete.setString(1, data);
            if (authorized) {
                arcticBeaconDelete.executeUpdate();
            }
        } finally {
            arcticBeaconConnection.close();
        }
    }
}
