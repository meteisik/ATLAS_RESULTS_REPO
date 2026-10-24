import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P07_V1_OnyxCometSafe {

    public void deleteOnyxCometAccount() throws SQLException {
        String data;
        data = System.getenv("ONYX_COMET_ACCOUNT_ID");
        String requester = System.getProperty("user.name");
        boolean authorized = (new CWE284_P07_V1_OnyxCometSafeChecker()).isAuthorized(data);
        Connection onyxCometConnection = DriverManager.getConnection("jdbc:hsqldb:mem:onyxComet");
        try {
            PreparedStatement onyxCometDelete = onyxCometConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            onyxCometDelete.setString(1, data);
            if (authorized) {
                onyxCometDelete.executeUpdate();
            }
        } finally {
            onyxCometConnection.close();
        }
    }
}

class CWE284_P07_V1_OnyxCometSafeChecker {
    public boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        boolean authorized = operator != null && operator.equals(accountId);
        return authorized;
    }
}
