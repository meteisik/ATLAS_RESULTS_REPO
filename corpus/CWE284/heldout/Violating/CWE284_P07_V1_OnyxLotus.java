import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P07_V1_OnyxLotus {

    public void deleteOnyxLotusAccount() throws SQLException {
        String data;
        data = System.getenv("ONYX_LOTUS_ACCOUNT_ID");
        String requester = System.getProperty("user.name");
        boolean authorized = (new CWE284_P07_V1_OnyxLotusChecker()).isAuthorized(requester);
        Connection onyxLotusConnection = DriverManager.getConnection("jdbc:hsqldb:mem:onyxLotus");
        try {
            PreparedStatement onyxLotusDelete = onyxLotusConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            onyxLotusDelete.setString(1, data);
            if (authorized) {
                onyxLotusDelete.executeUpdate();
            }
        } finally {
            onyxLotusConnection.close();
        }
    }
}

class CWE284_P07_V1_OnyxLotusChecker {
    public boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        boolean authorized = operator != null && operator.equals(accountId);
        return authorized;
    }
}
