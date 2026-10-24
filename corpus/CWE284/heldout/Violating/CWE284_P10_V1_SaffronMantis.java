import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P10_V1_SaffronMantis {

    public static String data;

    public static boolean authorized;

    public void deleteSaffronMantisAccount() throws SQLException {
        data = System.getenv("SAFFRON_MANTIS_ACCOUNT_ID");
        authorized = isAuthorized(data);
        (new CWE284_P10_V1_SaffronMantisSink()).applySaffronMantisDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P10_V1_SaffronMantisSink {
    public void applySaffronMantisDeletion() throws SQLException {
        String data = CWE284_P10_V1_SaffronMantis.data;
        boolean authorized = CWE284_P10_V1_SaffronMantis.authorized;
        Connection saffronMantisConnection = DriverManager.getConnection("jdbc:hsqldb:mem:saffronMantis");
        try {
            PreparedStatement saffronMantisDelete = saffronMantisConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            saffronMantisDelete.setString(1, data);
            saffronMantisDelete.executeUpdate();
            if (!authorized) {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            saffronMantisConnection.close();
        }
    }
}
