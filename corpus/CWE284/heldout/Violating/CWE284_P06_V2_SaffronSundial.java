import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P06_V2_SaffronSundial {

    public void deleteSaffronSundialAccount() throws SQLException {
        String data;
        data = null;
        for (int j = 0; j < 1; j++) {
            data = System.getenv("SAFFRON_SUNDIAL_ACCOUNT_ID");
        }
        boolean authorized = isAuthorized(data);
        (new CWE284_P06_V2_SaffronSundialSink()).applySaffronSundialDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P06_V2_SaffronSundialSink {
    public void applySaffronSundialDeletion(String data, boolean authorized) throws SQLException {
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
