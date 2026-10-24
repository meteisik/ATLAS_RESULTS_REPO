import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P07_V2_VelvetPrism {
    private static boolean privateTrue = true;

    public void deleteVelvetPrismAccount() throws SQLException {
        String data;
        if (privateTrue) {
            data = System.getenv("VELVET_PRISM_ACCOUNT_ID");
        } else {
            data = null;
        }
        String requester = System.getProperty("user.name");
        boolean authorized = (new CWE284_P07_V2_VelvetPrismChecker()).isAuthorized(requester);
        Connection velvetPrismConnection = DriverManager.getConnection("jdbc:hsqldb:mem:velvetPrism");
        try {
            PreparedStatement velvetPrismDelete = velvetPrismConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            velvetPrismDelete.setString(1, data);
            if (authorized) {
                velvetPrismDelete.executeUpdate();
            }
        } finally {
            velvetPrismConnection.close();
        }
    }
}

class CWE284_P07_V2_VelvetPrismChecker {
    public boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        boolean authorized = operator != null && operator.equals(accountId);
        return authorized;
    }
}
