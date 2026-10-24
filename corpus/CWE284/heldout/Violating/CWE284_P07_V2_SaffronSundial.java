import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P07_V2_SaffronSundial {

    public void deleteSaffronSundialAccount() throws SQLException {
        String data;
        if (5 == 5) {
            data = System.getenv("SAFFRON_SUNDIAL_ACCOUNT_ID");
        } else {
            data = null;
        }
        String requester = System.getProperty("user.name");
        boolean authorized = (new CWE284_P07_V2_SaffronSundialChecker()).isAuthorized(requester);
        Connection saffronSundialConnection = DriverManager.getConnection("jdbc:hsqldb:mem:saffronSundial");
        try {
            PreparedStatement saffronSundialDelete = saffronSundialConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            saffronSundialDelete.setString(1, data);
            if (authorized) {
                saffronSundialDelete.executeUpdate();
            }
        } finally {
            saffronSundialConnection.close();
        }
    }
}

class CWE284_P07_V2_SaffronSundialChecker {
    public boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        boolean authorized = operator != null && operator.equals(accountId);
        return authorized;
    }
}
