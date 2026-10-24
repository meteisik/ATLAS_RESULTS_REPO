import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P07_V1_OnyxNebulaSafe {

    public void deleteOnyxNebulaAccount() throws SQLException {
        String data;
        data = System.getenv("ONYX_NEBULA_ACCOUNT_ID");
        String requester = System.getProperty("user.name");
        boolean authorized = (new CWE284_P07_V1_OnyxNebulaSafeChecker()).isAuthorized(data);
        Connection onyxNebulaConnection = DriverManager.getConnection("jdbc:hsqldb:mem:onyxNebula");
        try {
            PreparedStatement onyxNebulaDelete = onyxNebulaConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            onyxNebulaDelete.setString(1, data);
            if (authorized) {
                onyxNebulaDelete.executeUpdate();
            }
        } finally {
            onyxNebulaConnection.close();
        }
    }
}

class CWE284_P07_V1_OnyxNebulaSafeChecker {
    public boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        boolean authorized = operator != null && operator.equals(accountId);
        return authorized;
    }
}
