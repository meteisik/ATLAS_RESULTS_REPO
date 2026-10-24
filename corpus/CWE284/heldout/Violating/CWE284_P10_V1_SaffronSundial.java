import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P10_V1_SaffronSundial {

    public static String data;

    public static boolean authorized;

    public void deleteSaffronSundialAccount() throws SQLException {
        data = System.getenv("SAFFRON_SUNDIAL_ACCOUNT_ID");
        authorized = isAuthorized(data);
        (new CWE284_P10_V1_SaffronSundialSink()).applySaffronSundialDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P10_V1_SaffronSundialSink {
    public void applySaffronSundialDeletion() throws SQLException {
        String data = CWE284_P10_V1_SaffronSundial.data;
        boolean authorized = CWE284_P10_V1_SaffronSundial.authorized;
        Connection saffronSundialConnection = DriverManager.getConnection("jdbc:hsqldb:mem:saffronSundial");
        try {
            PreparedStatement saffronSundialDelete = saffronSundialConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            saffronSundialDelete.setString(1, data);
            saffronSundialDelete.executeUpdate();
            if (!authorized) {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            saffronSundialConnection.close();
        }
    }
}
