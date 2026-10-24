import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P10_V1_VelvetQuartzSafe {

    public static String data;

    public static boolean authorized;

    public void deleteVelvetQuartzAccount() throws SQLException {
        data = System.getenv("VELVET_QUARTZ_ACCOUNT_ID");
        authorized = isAuthorized(data);
        (new CWE284_P10_V1_VelvetQuartzSafeSink()).applyVelvetQuartzDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P10_V1_VelvetQuartzSafeSink {
    public void applyVelvetQuartzDeletion() throws SQLException {
        String data = CWE284_P10_V1_VelvetQuartzSafe.data;
        boolean authorized = CWE284_P10_V1_VelvetQuartzSafe.authorized;
        Connection velvetQuartzConnection = DriverManager.getConnection("jdbc:hsqldb:mem:velvetQuartz");
        try {
            PreparedStatement velvetQuartzDelete = velvetQuartzConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            velvetQuartzDelete.setString(1, data);
            if (authorized) {
                velvetQuartzDelete.executeUpdate();
            } else {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            velvetQuartzConnection.close();
        }
    }
}
