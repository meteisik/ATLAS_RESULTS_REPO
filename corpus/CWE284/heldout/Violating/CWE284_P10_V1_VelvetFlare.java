import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P10_V1_VelvetFlare {

    public static String data;

    public static boolean authorized;

    public void deleteVelvetFlareAccount() throws SQLException {
        data = System.getenv("VELVET_FLARE_ACCOUNT_ID");
        authorized = isAuthorized(data);
        (new CWE284_P10_V1_VelvetFlareSink()).applyVelvetFlareDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P10_V1_VelvetFlareSink {
    public void applyVelvetFlareDeletion() throws SQLException {
        String data = CWE284_P10_V1_VelvetFlare.data;
        boolean authorized = CWE284_P10_V1_VelvetFlare.authorized;
        Connection velvetFlareConnection = DriverManager.getConnection("jdbc:hsqldb:mem:velvetFlare");
        try {
            PreparedStatement velvetFlareDelete = velvetFlareConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            velvetFlareDelete.setString(1, data);
            velvetFlareDelete.executeUpdate();
            if (!authorized) {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            velvetFlareConnection.close();
        }
    }
}
