import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P07_V2_VelvetFlare {

    public void deleteVelvetFlareAccount() throws SQLException {
        String data;
        if (true) {
            data = System.getenv("VELVET_FLARE_ACCOUNT_ID");
        } else {
            data = null;
        }
        String requester = System.getProperty("user.name");
        boolean authorized = (new CWE284_P07_V2_VelvetFlareChecker()).isAuthorized(requester);
        Connection velvetFlareConnection = DriverManager.getConnection("jdbc:hsqldb:mem:velvetFlare");
        try {
            PreparedStatement velvetFlareDelete = velvetFlareConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            velvetFlareDelete.setString(1, data);
            if (authorized) {
                velvetFlareDelete.executeUpdate();
            }
        } finally {
            velvetFlareConnection.close();
        }
    }
}

class CWE284_P07_V2_VelvetFlareChecker {
    public boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        boolean authorized = operator != null && operator.equals(accountId);
        return authorized;
    }
}
