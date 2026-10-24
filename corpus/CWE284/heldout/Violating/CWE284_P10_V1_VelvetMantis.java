import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P10_V1_VelvetMantis {

    public static String data;

    public static boolean authorized;

    public void deleteVelvetMantisAccount() throws SQLException {
        data = System.getenv("VELVET_MANTIS_ACCOUNT_ID");
        authorized = isAuthorized(data);
        (new CWE284_P10_V1_VelvetMantisSink()).applyVelvetMantisDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P10_V1_VelvetMantisSink {
    public void applyVelvetMantisDeletion() throws SQLException {
        String data = CWE284_P10_V1_VelvetMantis.data;
        boolean authorized = CWE284_P10_V1_VelvetMantis.authorized;
        Connection velvetMantisConnection = DriverManager.getConnection("jdbc:hsqldb:mem:velvetMantis");
        try {
            PreparedStatement velvetMantisDelete = velvetMantisConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            velvetMantisDelete.setString(1, data);
            velvetMantisDelete.executeUpdate();
            if (!authorized) {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            velvetMantisConnection.close();
        }
    }
}
