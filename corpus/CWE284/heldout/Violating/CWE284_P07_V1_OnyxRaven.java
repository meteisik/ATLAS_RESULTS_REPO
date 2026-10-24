import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P07_V1_OnyxRaven {

    public void deleteOnyxRavenAccount() throws SQLException {
        String data;
        data = System.getenv("ONYX_RAVEN_ACCOUNT_ID");
        String requester = System.getProperty("user.name");
        boolean authorized = (new CWE284_P07_V1_OnyxRavenChecker()).isAuthorized(requester);
        Connection onyxRavenConnection = DriverManager.getConnection("jdbc:hsqldb:mem:onyxRaven");
        try {
            PreparedStatement onyxRavenDelete = onyxRavenConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            onyxRavenDelete.setString(1, data);
            if (authorized) {
                onyxRavenDelete.executeUpdate();
            }
        } finally {
            onyxRavenConnection.close();
        }
    }
}

class CWE284_P07_V1_OnyxRavenChecker {
    public boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        boolean authorized = operator != null && operator.equals(accountId);
        return authorized;
    }
}
