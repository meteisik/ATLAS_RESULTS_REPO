import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P07_V2_VelvetQuartzSafe {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public void deleteVelvetQuartzAccount() throws SQLException {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("VELVET_QUARTZ_ACCOUNT_ID");
        } else {
            data = null;
        }
        String requester = System.getProperty("user.name");
        boolean authorized = (new CWE284_P07_V2_VelvetQuartzSafeChecker()).isAuthorized(data);
        Connection velvetQuartzConnection = DriverManager.getConnection("jdbc:hsqldb:mem:velvetQuartz");
        try {
            PreparedStatement velvetQuartzDelete = velvetQuartzConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            velvetQuartzDelete.setString(1, data);
            if (authorized) {
                velvetQuartzDelete.executeUpdate();
            }
        } finally {
            velvetQuartzConnection.close();
        }
    }
}

class CWE284_P07_V2_VelvetQuartzSafeChecker {
    public boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        boolean authorized = operator != null && operator.equals(accountId);
        return authorized;
    }
}
