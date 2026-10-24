import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P10_V1_VelvetCascadeSafe {

    public static String data;

    public static boolean authorized;

    public void deleteVelvetCascadeAccount() throws SQLException {
        data = System.getenv("VELVET_CASCADE_ACCOUNT_ID");
        authorized = isAuthorized(data);
        (new CWE284_P10_V1_VelvetCascadeSafeSink()).applyVelvetCascadeDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P10_V1_VelvetCascadeSafeSink {
    public void applyVelvetCascadeDeletion() throws SQLException {
        String data = CWE284_P10_V1_VelvetCascadeSafe.data;
        boolean authorized = CWE284_P10_V1_VelvetCascadeSafe.authorized;
        Connection velvetCascadeConnection = DriverManager.getConnection("jdbc:hsqldb:mem:velvetCascade");
        try {
            PreparedStatement velvetCascadeDelete = velvetCascadeConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            velvetCascadeDelete.setString(1, data);
            if (authorized) {
                velvetCascadeDelete.executeUpdate();
            } else {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            velvetCascadeConnection.close();
        }
    }
}
