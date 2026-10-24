import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P07_V2_VelvetSundial {
    private static boolean privateReturnsTrue() { return true; }

    public void deleteVelvetSundialAccount() throws SQLException {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("VELVET_SUNDIAL_ACCOUNT_ID");
        } else {
            data = null;
        }
        String requester = System.getProperty("user.name");
        boolean authorized = (new CWE284_P07_V2_VelvetSundialChecker()).isAuthorized(requester);
        Connection velvetSundialConnection = DriverManager.getConnection("jdbc:hsqldb:mem:velvetSundial");
        try {
            PreparedStatement velvetSundialDelete = velvetSundialConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            velvetSundialDelete.setString(1, data);
            if (authorized) {
                velvetSundialDelete.executeUpdate();
            }
        } finally {
            velvetSundialConnection.close();
        }
    }
}

class CWE284_P07_V2_VelvetSundialChecker {
    public boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        boolean authorized = operator != null && operator.equals(accountId);
        return authorized;
    }
}
