import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P10_V2_AmberFlareSafe {

    public static String data;

    public static boolean authorized;

    public void deleteAmberFlareAccount() throws SQLException {
        if (5 == 5) {
            data = System.getenv("AMBER_FLARE_ACCOUNT_ID");
        } else {
            data = null;
        }
        authorized = isAuthorized(data);
        (new CWE284_P10_V2_AmberFlareSafeSink()).applyAmberFlareDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P10_V2_AmberFlareSafeSink {
    public void applyAmberFlareDeletion() throws SQLException {
        String data = CWE284_P10_V2_AmberFlareSafe.data;
        boolean authorized = CWE284_P10_V2_AmberFlareSafe.authorized;
        Connection amberFlareConnection = DriverManager.getConnection("jdbc:hsqldb:mem:amberFlare");
        try {
            PreparedStatement amberFlareDelete = amberFlareConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            amberFlareDelete.setString(1, data);
            if (authorized) {
                amberFlareDelete.executeUpdate();
            } else {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            amberFlareConnection.close();
        }
    }
}
