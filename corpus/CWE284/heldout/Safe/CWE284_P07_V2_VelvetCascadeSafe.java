import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P07_V2_VelvetCascadeSafe {

    public void deleteVelvetCascadeAccount() throws SQLException {
        String data;
        while (true) {
            data = System.getenv("VELVET_CASCADE_ACCOUNT_ID");
            break;
        }
        String requester = System.getProperty("user.name");
        boolean authorized = (new CWE284_P07_V2_VelvetCascadeSafeChecker()).isAuthorized(data);
        Connection velvetCascadeConnection = DriverManager.getConnection("jdbc:hsqldb:mem:velvetCascade");
        try {
            PreparedStatement velvetCascadeDelete = velvetCascadeConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            velvetCascadeDelete.setString(1, data);
            if (authorized) {
                velvetCascadeDelete.executeUpdate();
            }
        } finally {
            velvetCascadeConnection.close();
        }
    }
}

class CWE284_P07_V2_VelvetCascadeSafeChecker {
    public boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        boolean authorized = operator != null && operator.equals(accountId);
        return authorized;
    }
}
