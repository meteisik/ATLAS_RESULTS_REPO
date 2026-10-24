import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.HashMap;

public class CWE284_P11_V2_ArcticHarborSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void deleteArcticHarborAccount() throws SQLException {
        String data;
        if (IO.staticFive == 5) {
            data = System.getenv("ARCTIC_HARBOR_ACCOUNT_ID");
        } else {
            data = null;
        }
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(data);
        HashMap<Integer, Boolean> decisions = new HashMap<Integer, Boolean>();
        decisions.put(0, authorized);
        decisions.put(1, authorized);
        decisions.put(2, authorized);
        (new CWE284_P11_V2_ArcticHarborSafeSink()).applyArcticHarborDeletion(data, decisions);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P11_V2_ArcticHarborSafeSink {
    public void applyArcticHarborDeletion(String data, HashMap<Integer, Boolean> decisions) throws SQLException {
        boolean authorized = decisions.get(2);
        Connection arcticHarborConnection = DriverManager.getConnection("jdbc:hsqldb:mem:arcticHarbor");
        try {
            PreparedStatement arcticHarborDelete = arcticHarborConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            arcticHarborDelete.setString(1, data);
            if (authorized) {
                arcticHarborDelete.executeUpdate();
            }
        } finally {
            arcticHarborConnection.close();
        }
    }
}
