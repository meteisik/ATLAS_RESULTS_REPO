import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P10_V1_SaffronFlareSafe {

    public static String data;

    public static boolean authorized;

    public void deleteSaffronFlareAccount() throws SQLException {
        data = System.getenv("SAFFRON_FLARE_ACCOUNT_ID");
        authorized = isAuthorized(data);
        (new CWE284_P10_V1_SaffronFlareSafeSink()).applySaffronFlareDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P10_V1_SaffronFlareSafeSink {
    public void applySaffronFlareDeletion() throws SQLException {
        String data = CWE284_P10_V1_SaffronFlareSafe.data;
        boolean authorized = CWE284_P10_V1_SaffronFlareSafe.authorized;
        Connection saffronFlareConnection = DriverManager.getConnection("jdbc:hsqldb:mem:saffronFlare");
        try {
            PreparedStatement saffronFlareDelete = saffronFlareConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            saffronFlareDelete.setString(1, data);
            if (authorized) {
                saffronFlareDelete.executeUpdate();
            } else {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            saffronFlareConnection.close();
        }
    }
}
