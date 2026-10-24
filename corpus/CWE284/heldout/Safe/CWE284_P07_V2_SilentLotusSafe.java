import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P07_V2_SilentLotusSafe {
    private static boolean privateReturnsTrue() { return true; }

    public void deleteSilentLotusAccount() throws SQLException {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("SILENT_LOTUS_ACCOUNT_ID");
        } else {
            data = null;
        }
        String requester = System.getProperty("user.name");
        boolean authorized = (new CWE284_P07_V2_SilentLotusSafeChecker()).isAuthorized(data);
        Connection silentLotusConnection = DriverManager.getConnection("jdbc:hsqldb:mem:silentLotus");
        try {
            PreparedStatement silentLotusDelete = silentLotusConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            silentLotusDelete.setString(1, data);
            if (authorized) {
                silentLotusDelete.executeUpdate();
            }
        } finally {
            silentLotusConnection.close();
        }
    }
}

class CWE284_P07_V2_SilentLotusSafeChecker {
    public boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        boolean authorized = operator != null && operator.equals(accountId);
        return authorized;
    }
}
