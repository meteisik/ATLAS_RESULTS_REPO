import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P10_V2_ArcticRavenSafe {

    public static String data;

    public static boolean authorized;

    public void deleteArcticRavenAccount() throws SQLException {
        if (5 == 5) {
            data = System.getenv("ARCTIC_RAVEN_ACCOUNT_ID");
        } else {
            data = null;
        }
        authorized = isAuthorized(data);
        (new CWE284_P10_V2_ArcticRavenSafeSink()).applyArcticRavenDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P10_V2_ArcticRavenSafeSink {
    public void applyArcticRavenDeletion() throws SQLException {
        String data = CWE284_P10_V2_ArcticRavenSafe.data;
        boolean authorized = CWE284_P10_V2_ArcticRavenSafe.authorized;
        Connection arcticRavenConnection = DriverManager.getConnection("jdbc:hsqldb:mem:arcticRaven");
        try {
            PreparedStatement arcticRavenDelete = arcticRavenConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            arcticRavenDelete.setString(1, data);
            if (authorized) {
                arcticRavenDelete.executeUpdate();
            } else {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            arcticRavenConnection.close();
        }
    }
}
