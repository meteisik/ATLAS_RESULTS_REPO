import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P10_V1_VelvetPrism {

    public static String data;

    public static boolean authorized;

    public void deleteVelvetPrismAccount() throws SQLException {
        data = System.getenv("VELVET_PRISM_ACCOUNT_ID");
        authorized = isAuthorized(data);
        (new CWE284_P10_V1_VelvetPrismSink()).applyVelvetPrismDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P10_V1_VelvetPrismSink {
    public void applyVelvetPrismDeletion() throws SQLException {
        String data = CWE284_P10_V1_VelvetPrism.data;
        boolean authorized = CWE284_P10_V1_VelvetPrism.authorized;
        Connection velvetPrismConnection = DriverManager.getConnection("jdbc:hsqldb:mem:velvetPrism");
        try {
            PreparedStatement velvetPrismDelete = velvetPrismConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            velvetPrismDelete.setString(1, data);
            velvetPrismDelete.executeUpdate();
            if (!authorized) {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            velvetPrismConnection.close();
        }
    }
}
