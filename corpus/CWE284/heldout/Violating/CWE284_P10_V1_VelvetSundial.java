import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P10_V1_VelvetSundial {

    public static String data;

    public static boolean authorized;

    public void deleteVelvetSundialAccount() throws SQLException {
        data = System.getenv("VELVET_SUNDIAL_ACCOUNT_ID");
        authorized = isAuthorized(data);
        (new CWE284_P10_V1_VelvetSundialSink()).applyVelvetSundialDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P10_V1_VelvetSundialSink {
    public void applyVelvetSundialDeletion() throws SQLException {
        String data = CWE284_P10_V1_VelvetSundial.data;
        boolean authorized = CWE284_P10_V1_VelvetSundial.authorized;
        Connection velvetSundialConnection = DriverManager.getConnection("jdbc:hsqldb:mem:velvetSundial");
        try {
            PreparedStatement velvetSundialDelete = velvetSundialConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            velvetSundialDelete.setString(1, data);
            velvetSundialDelete.executeUpdate();
            if (!authorized) {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            velvetSundialConnection.close();
        }
    }
}
