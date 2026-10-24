import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P07_V2_SilentHarborSafe {
    private static boolean privateTrue = true;

    public void deleteSilentHarborAccount() throws SQLException {
        String data;
        if (privateTrue) {
            data = System.getenv("SILENT_HARBOR_ACCOUNT_ID");
        } else {
            data = null;
        }
        String requester = System.getProperty("user.name");
        boolean authorized = (new CWE284_P07_V2_SilentHarborSafeChecker()).isAuthorized(data);
        Connection silentHarborConnection = DriverManager.getConnection("jdbc:hsqldb:mem:silentHarbor");
        try {
            PreparedStatement silentHarborDelete = silentHarborConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            silentHarborDelete.setString(1, data);
            if (authorized) {
                silentHarborDelete.executeUpdate();
            }
        } finally {
            silentHarborConnection.close();
        }
    }
}

class CWE284_P07_V2_SilentHarborSafeChecker {
    public boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        boolean authorized = operator != null && operator.equals(accountId);
        return authorized;
    }
}
