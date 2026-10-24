import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P08_V2_SaffronSundialSafe {
    private static boolean privateTrue = true;

    public void deleteSaffronSundialAccount() throws SQLException {
        String data;
        if (privateTrue) {
            data = System.getenv("SAFFRON_SUNDIAL_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean[] decisions = new boolean[5];
        decisions[2] = isAuthorized(data);
        (new CWE284_P08_V2_SaffronSundialSafeSink()).applySaffronSundialDeletion(data, decisions);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P08_V2_SaffronSundialSafeSink {
    public void applySaffronSundialDeletion(String data, boolean[] decisions) throws SQLException {
        boolean authorized = decisions[2];
        Connection saffronSundialConnection = DriverManager.getConnection("jdbc:hsqldb:mem:saffronSundial");
        try {
            PreparedStatement saffronSundialDelete = saffronSundialConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            saffronSundialDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                saffronSundialDelete.executeUpdate();
            }
        } finally {
            saffronSundialConnection.close();
        }
    }
}
