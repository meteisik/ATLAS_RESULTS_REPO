import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P07_V2_SaffronMantisSafe {

    public void deleteSaffronMantisAccount() throws SQLException {
        String data;
        switch (7) {
        case 7:
            data = System.getenv("SAFFRON_MANTIS_ACCOUNT_ID");
            break;
        default:
            data = null;
            break;
        }
        String requester = System.getProperty("user.name");
        boolean authorized = (new CWE284_P07_V2_SaffronMantisSafeChecker()).isAuthorized(data);
        Connection saffronMantisConnection = DriverManager.getConnection("jdbc:hsqldb:mem:saffronMantis");
        try {
            PreparedStatement saffronMantisDelete = saffronMantisConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            saffronMantisDelete.setString(1, data);
            if (authorized) {
                saffronMantisDelete.executeUpdate();
            }
        } finally {
            saffronMantisConnection.close();
        }
    }
}

class CWE284_P07_V2_SaffronMantisSafeChecker {
    public boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        boolean authorized = operator != null && operator.equals(accountId);
        return authorized;
    }
}
