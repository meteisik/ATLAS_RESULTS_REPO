import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P10_V1_VelvetMantisSafe {

    public static String data;

    public static boolean authorized;

    public void deleteVelvetMantisAccount() throws SQLException {
        data = System.getenv("VELVET_MANTIS_ACCOUNT_ID");
        authorized = isAuthorized(data);
        (new CWE284_P10_V1_VelvetMantisSafeSink()).applyVelvetMantisDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P10_V1_VelvetMantisSafeSink {
    public void applyVelvetMantisDeletion() throws SQLException {
        String data = CWE284_P10_V1_VelvetMantisSafe.data;
        boolean authorized = CWE284_P10_V1_VelvetMantisSafe.authorized;
        Connection velvetMantisConnection = DriverManager.getConnection("jdbc:hsqldb:mem:velvetMantis");
        try {
            PreparedStatement velvetMantisDelete = velvetMantisConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            velvetMantisDelete.setString(1, data);
            if (authorized) {
                velvetMantisDelete.executeUpdate();
            } else {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            velvetMantisConnection.close();
        }
    }
}
