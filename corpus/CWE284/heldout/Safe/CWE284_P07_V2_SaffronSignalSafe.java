import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P07_V2_SaffronSignalSafe {

    public void deleteSaffronSignalAccount() throws SQLException {
        String data;
        if (true) {
            data = System.getenv("SAFFRON_SIGNAL_ACCOUNT_ID");
        } else {
            data = null;
        }
        String requester = System.getProperty("user.name");
        boolean authorized = (new CWE284_P07_V2_SaffronSignalSafeChecker()).isAuthorized(data);
        Connection saffronSignalConnection = DriverManager.getConnection("jdbc:hsqldb:mem:saffronSignal");
        try {
            PreparedStatement saffronSignalDelete = saffronSignalConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            saffronSignalDelete.setString(1, data);
            if (authorized) {
                saffronSignalDelete.executeUpdate();
            }
        } finally {
            saffronSignalConnection.close();
        }
    }
}

class CWE284_P07_V2_SaffronSignalSafeChecker {
    public boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        boolean authorized = operator != null && operator.equals(accountId);
        return authorized;
    }
}
