import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P07_V1_OnyxOrbit {

    public void deleteOnyxOrbitAccount() throws SQLException {
        String data;
        data = System.getenv("ONYX_ORBIT_ACCOUNT_ID");
        String requester = System.getProperty("user.name");
        boolean authorized = (new CWE284_P07_V1_OnyxOrbitChecker()).isAuthorized(requester);
        Connection onyxOrbitConnection = DriverManager.getConnection("jdbc:hsqldb:mem:onyxOrbit");
        try {
            PreparedStatement onyxOrbitDelete = onyxOrbitConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            onyxOrbitDelete.setString(1, data);
            if (authorized) {
                onyxOrbitDelete.executeUpdate();
            }
        } finally {
            onyxOrbitConnection.close();
        }
    }
}

class CWE284_P07_V1_OnyxOrbitChecker {
    public boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        boolean authorized = operator != null && operator.equals(accountId);
        return authorized;
    }
}
