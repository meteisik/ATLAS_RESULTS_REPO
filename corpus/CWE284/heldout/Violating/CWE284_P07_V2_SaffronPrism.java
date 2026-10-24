import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P07_V2_SaffronPrism {

    public void deleteSaffronPrismAccount() throws SQLException {
        String data;
        while (true) {
            data = System.getenv("SAFFRON_PRISM_ACCOUNT_ID");
            break;
        }
        String requester = System.getProperty("user.name");
        boolean authorized = (new CWE284_P07_V2_SaffronPrismChecker()).isAuthorized(requester);
        Connection saffronPrismConnection = DriverManager.getConnection("jdbc:hsqldb:mem:saffronPrism");
        try {
            PreparedStatement saffronPrismDelete = saffronPrismConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            saffronPrismDelete.setString(1, data);
            if (authorized) {
                saffronPrismDelete.executeUpdate();
            }
        } finally {
            saffronPrismConnection.close();
        }
    }
}

class CWE284_P07_V2_SaffronPrismChecker {
    public boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        boolean authorized = operator != null && operator.equals(accountId);
        return authorized;
    }
}
